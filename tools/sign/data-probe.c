/**
 * 读取钉钉进程中 SDK 的运行时数据
 *
 * 思路：SDK 的 .data 段里有 token 缓存（全局变量），
 * 只需 基址 + RVA 就能读出已初始化的内容。
 *
 * 编译：cl /nologo /O2 /Fe:data-probe.exe data-probe.c advapi32.lib Psapi.lib
 */
#include <windows.h>
#include <stdio.h>
#include <tlhelp32.h>
#include <psapi.h>
#include <string.h>

/* SDK 的 .data 段（从 PE 节表）：RVA 0xa16000，大小 0x61d88 */
#define SDK_DATA_RVA   0xa16000
#define SDK_DATA_SIZE  0x61d88

static DWORD find_pid(void) {
    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    PROCESSENTRY32 pe = { sizeof(pe) };
    DWORD best = 0; SIZE_T bestWs = 0;
    if (Process32First(snap, &pe)) do {
        if (_stricmp(pe.szExeFile, "DingTalk.exe") == 0) {
            HANDLE h = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pe.th32ProcessID);
            if (h) {
                PROCESS_MEMORY_COUNTERS pmc;
                if (GetProcessMemoryInfo(h, &pmc, sizeof(pmc)) && pmc.WorkingSetSize > bestWs) {
                    bestWs = pmc.WorkingSetSize; best = pe.th32ProcessID;
                }
                CloseHandle(h);
            }
        }
    } while (Process32Next(snap, &pe));
    CloseHandle(snap);
    return best;
}

static ULONG_PTR find_module(DWORD pid, const char *name, DWORD *outSize, char *outPath, DWORD pathLen) {
    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, pid);
    if (snap == INVALID_HANDLE_VALUE) return 0;
    MODULEENTRY32 me = { sizeof(me) };
    ULONG_PTR base = 0;
    if (Module32First(snap, &me)) do {
        if (_stricmp(me.szModule, name) == 0) {
            base = (ULONG_PTR)me.modBaseAddr;
            *outSize = me.modBaseSize;
            if (outPath) strncpy(outPath, me.szExePath, pathLen - 1);
            break;
        }
    } while (Module32Next(snap, &me));
    CloseHandle(snap);
    return base;
}

/** 判断某段内存是否可读（读一字节探测） */
static int readable(HANDLE h, ULONG_PTR addr) {
    unsigned char c;
    SIZE_T got;
    return ReadProcessMemory(h, (LPCVOID)addr, &c, 1, &got) && got == 1;
}

static int is_printable_run(const unsigned char *p, int n) {
    int cnt = 0;
    for (int i = 0; i < n; i++) {
        unsigned char c = p[i];
        if ((c >= 0x20 && c < 0x7f) || c == '\r' || c == '\n' || c == '\t') cnt++;
        else if (c == 0) break;
        else return 0;
    }
    return cnt >= n;
}

int main(void) {
    SetConsoleOutputCP(CP_UTF8);
    printf("=== SDK 运行时数据探针 ===\n");

    DWORD pid = find_pid();
    if (!pid) { printf("未找到 DingTalk.exe\n"); return 1; }
    printf("PID = %lu\n", pid);

    HANDLE h = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, pid);
    if (!h) { printf("OpenProcess 失败 %lu\n", GetLastError()); return 2; }

    DWORD sdkSize = 0; char sdkPath[MAX_PATH] = {0};
    ULONG_PTR sdkBase = find_module(pid, "SecurityGuardSDK64.dll", &sdkSize, sdkPath, MAX_PATH);
    if (!sdkBase) { printf("SDK 未加载\n"); return 3; }
    printf("SDK 基址 %p，大小 0x%x\n", (void *)sdkBase, sdkSize);

    /* 读 .data 段 */
    ULONG_PTR dataAddr = sdkBase + SDK_DATA_RVA;
    printf("\n== SDK .data 段 (RVA 0x%x) ==\n", SDK_DATA_RVA);
    printf("运行时地址 %p，大小 0x%x\n", (void *)dataAddr, SDK_DATA_SIZE);

    unsigned char *buf = (unsigned char *)malloc(SDK_DATA_SIZE);
    if (!buf) { printf("内存不足\n"); return 4; }

    SIZE_T got = 0;
    if (!ReadProcessMemory(h, (LPCVOID)dataAddr, buf, SDK_DATA_SIZE, &got)) {
        printf("读 .data 失败: %lu (已读 %llu)\n", GetLastError(), (unsigned long long)got);
        free(buf);
        return 5;
    }
    printf("读取成功 %llu 字节\n", (unsigned long long)got);

    /* 统计非零密度 */
    int nonzero = 0;
    for (DWORD i = 0; i < SDK_DATA_SIZE; i++) if (buf[i]) nonzero++;
    printf("非零字节: %d / %u (%.1f%%)\n", nonzero, SDK_DATA_SIZE, nonzero * 100.0 / SDK_DATA_SIZE);

    /* 找可打印字符串（>= 16 字节连续） */
    printf("\n== .data 中的字符串（>=16 字节连续可打印）==\n");
    int found = 0;
    for (DWORD i = 0; i + 16 < SDK_DATA_SIZE && found < 60; ) {
        if (is_printable_run(buf + i, 16)) {
            /* 找结尾 */
            DWORD end = i;
            while (end < SDK_DATA_SIZE && buf[end] && (buf[end] >= 0x20 && buf[end] < 0x7f)) end++;
            DWORD len = end - i;
            if (len >= 16 && len <= 300) {
                printf("  [+0x%06x] %.*s\n", i, (int)(len > 120 ? 120 : len), buf + i);
                found++;
            }
            i = end + 1;
        } else i++;
    }
    printf("共找到 %d 条\n", found);

    /* 找形如 x5-sign / token 的长 base64 串 */
    printf("\n== 疑似 token（>=64 字节 base64 字符）==\n");
    int tok = 0;
    for (DWORD i = 0; i + 64 < SDK_DATA_SIZE && tok < 20; ) {
        int ok = 1;
        DWORD j = i;
        for (; j < SDK_DATA_SIZE && j < i + 400; j++) {
            unsigned char c = buf[j];
            if (!((c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') ||
                  (c >= '0' && c <= '9') || c == '+' || c == '/' || c == '=' || c == '-' || c == '_')) {
                ok = 0; break;
            }
        }
        DWORD len = j - i;
        if (ok && len >= 64) {
            printf("  [+0x%06x] len=%u  %.80s...\n", i, len, buf + i);
            tok++;
            i = j + 1;
        } else i++;
    }
    printf("共找到 %d 条\n", tok);

    free(buf);
    CloseHandle(h);
    return 0;
}
