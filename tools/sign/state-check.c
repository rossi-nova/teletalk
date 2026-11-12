/**
 * SDK 运行时状态检查
 *
 * 判断钉钉进程里的 SDK 是否已初始化、是否已生成过 token。
 * 方法：扫描 SDK 的整个可读映像，找 base64 特征串与 x5- 头。
 *
 * 编译：cl /nologo /O2 /Fe:state-check.exe state-check.c advapi32.lib Psapi.lib
 */
#include <windows.h>
#include <stdio.h>
#include <tlhelp32.h>
#include <psapi.h>
#include <string.h>

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

static ULONG_PTR find_module(DWORD pid, const char *name, DWORD *outSize) {
    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, pid);
    if (snap == INVALID_HANDLE_VALUE) return 0;
    MODULEENTRY32 me = { sizeof(me) };
    ULONG_PTR base = 0;
    if (Module32First(snap, &me)) do {
        if (_stricmp(me.szModule, name) == 0) { base = (ULONG_PTR)me.modBaseAddr; *outSize = me.modBaseSize; break; }
    } while (Module32Next(snap, &me));
    CloseHandle(snap);
    return base;
}

/** 在 [start,end) 搜 ASCII 子串 */
static int search(HANDLE h, ULONG_PTR start, ULONG_PTR end, const char *needle, int maxHits, int showCtx) {
    size_t nlen = strlen(needle);
    const SIZE_T CHUNK = 1 << 20;
    unsigned char *buf = (unsigned char *)malloc(CHUNK + nlen);
    int hits = 0;
    if (!buf) return 0;

    for (ULONG_PTR p = start; p < end && hits < maxHits; p += CHUNK) {
        SIZE_T want = (SIZE_T)((end - p) < CHUNK ? (end - p) : CHUNK);
        SIZE_T got = 0;
        if (!ReadProcessMemory(h, (LPCVOID)p, buf, want, &got) || got < nlen) continue;
        for (SIZE_T i = 0; i + nlen <= got; i++) {
            if (memcmp(buf + i, needle, nlen) == 0) {
                printf("  命中 @ 0x%llx", (unsigned long long)(p + i));
                if (showCtx) {
                    int s = (int)i - 16; if (s < 0) s = 0;
                    int e = (int)i + 80; if ((SIZE_T)e > got) e = (int)got;
                    printf("  ...");
                    for (int k = s; k < e; k++) {
                        unsigned char c = buf[k];
                        putchar((c >= 0x20 && c < 0x7f) ? c : '.');
                    }
                }
                printf("\n");
                if (++hits >= maxHits) break;
                i += nlen - 1;
            }
        }
    }
    free(buf);
    return hits;
}

int main(void) {
    SetConsoleOutputCP(CP_UTF8);
    printf("=== SDK 运行时状态 ===\n");

    DWORD pid = find_pid();
    HANDLE h = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, pid);
    if (!h) { printf("OpenProcess 失败 %lu\n", GetLastError()); return 2; }

    DWORD sdkSize = 0;
    ULONG_PTR base = find_module(pid, "SecurityGuardSDK64.dll", &sdkSize);
    printf("PID=%lu  SDK=%p  size=0x%x\n\n", pid, (void *)base, sdkSize);

    printf("== 搜 SDK 映像（x5- 头）==\n");
    search(h, base, base + sdkSize, "x5-sign", 5, 1);
    search(h, base, base + sdkSize, "x-sign:", 5, 1);
    search(h, base, base + sdkSize, "x-devid:", 5, 1);
    search(h, base, base + sdkSize, "x-utdid:", 5, 1);

    printf("\n== 搜进程堆（x5-sign）==\n");
    search(h, 0, (ULONG_PTR)1 << 47, "x5-sign", 8, 1);

    printf("\n== 搜 16 进制 token 特征（>=48 字节 base64）==\n");
    /* 扫堆找长 base64 串 */
    MEMORY_BASIC_INFORMATION mbi;
    ULONG_PTR addr = 0;
    int found = 0;
    const SIZE_T CHUNK = 1 << 20;
    unsigned char *buf = (unsigned char *)malloc(CHUNK);

    while (VirtualQueryEx(h, (LPCVOID)addr, &mbi, sizeof(mbi)) && found < 15) {
        if (mbi.State == MEM_COMMIT &&
            (mbi.Protect == PAGE_READWRITE || mbi.Protect == PAGE_READONLY ||
             mbi.Protect == PAGE_WRITECOPY)) {
            ULONG_PTR rs = (ULONG_PTR)mbi.BaseAddress, re = rs + mbi.RegionSize;
            for (ULONG_PTR q = rs; q < re && found < 15; q += CHUNK) {
                SIZE_T want = (SIZE_T)((re - q) < CHUNK ? (re - q) : CHUNK);
                SIZE_T got = 0;
                if (!ReadProcessMemory(h, (LPCVOID)q, buf, want, &got)) continue;
                for (SIZE_T i = 0; i + 48 <= got && found < 15; i++) {
                    int ok = 1; SIZE_T j = i;
                    for (; j < got && j < i + 512; j++) {
                        unsigned char c = buf[j];
                        if (!((c>='A'&&c<='Z')||(c>='a'&&c<='z')||(c>='0'&&c<='9')||c=='+'||c=='/'||c=='=')) { ok=0; break; }
                    }
                    SIZE_T len = j - i;
                    if (ok && len >= 64) {
                        printf("  0x%llx  len=%u  %.70s...\n",
                               (unsigned long long)(q + i), (unsigned)len, buf + i);
                        found++;
                        i = j;
                    }
                }
            }
        }
        addr = (ULONG_PTR)mbi.BaseAddress + mbi.RegionSize;
        if (addr < (ULONG_PTR)mbi.BaseAddress) break;
    }
    printf("共 %d 条\n", found);

    free(buf);
    CloseHandle(h);
    return 0;
}
