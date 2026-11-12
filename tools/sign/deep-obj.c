/**
 * 深挖签名请求对象
 *
 * 已发现对象 @ 0x23649a3e000：
 *   +0x00  "/IgetAuthTmpCode"（内联于 std::string SSO 缓冲）
 *   +0x20  → token "wzMK2c002xAAJ6..."
 *   +0x28  时间戳（FILETIME 形态）
 *
 * 打印完整对象 + 追踪所有字符串成员。
 *
 * 编译：cl /nologo /O2 /Fe:deep-obj.exe deep-obj.c advapi32.lib Psapi.lib
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

static ULONG_PTR find_module(DWORD pid, const char *name, DWORD *sz) {
    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, pid);
    if (snap == INVALID_HANDLE_VALUE) return 0;
    MODULEENTRY32 me = { sizeof(me) };
    ULONG_PTR base = 0;
    if (Module32First(snap, &me)) do {
        if (_stricmp(me.szModule, name) == 0) { base = (ULONG_PTR)me.modBaseAddr; if (sz) *sz = me.modBaseSize; break; }
    } while (Module32Next(snap, &me));
    CloseHandle(snap);
    return base;
}

static ULONG_PTR g_sdkBase, g_sdkEnd;

/** 判断指针是否可读 */
static int readable(HANDLE h, ULONG_PTR a, SIZE_T n) {
    MEMORY_BASIC_INFORMATION mbi;
    if (!VirtualQueryEx(h, (LPCVOID)a, &mbi, sizeof(mbi))) return 0;
    if (mbi.State != MEM_COMMIT) return 0;
    if (mbi.Protect & (PAGE_NOACCESS | PAGE_GUARD)) return 0;
    return a + n <= (ULONG_PTR)mbi.BaseAddress + mbi.RegionSize;
}

/** 打印 8 字节字段：数值/指针/字符串 */
static void field(HANDLE h, ULONG_PTR obj, int off, const unsigned char *raw) {
    ULONG_PTR v;
    memcpy(&v, raw + off, 8);
    printf("  +0x%02x  %016llx  ", off, (unsigned long long)v);

    if (!v) { printf("NULL"); return; }
    if (v >= g_sdkBase && v < g_sdkEnd) { printf("SDK+0x%llx", (unsigned long long)(v - g_sdkBase)); return; }

    /* 尝试读成字符串 */
    if (readable(h, v, 16)) {
        char s[96] = {0};
        SIZE_T g = 0;
        if (ReadProcessMemory(h, (LPCVOID)v, s, sizeof(s) - 1, &g) && g >= 4) {
            int pr = 0;
            for (SIZE_T i = 0; i < g && i < 60; i++) {
                if (s[i] >= 0x20 && s[i] < 0x7f) pr++; else break;
            }
            if (pr >= 4) { printf("\"%s\"", s); return; }
        }
    }
    printf("ptr 0x%llx", (unsigned long long)v);
}

int main(int argc, char **argv) {
    SetConsoleOutputCP(CP_UTF8);
    printf("=== 签名请求对象深挖 ===\n");

    DWORD pid = find_pid();
    HANDLE h = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, pid);
    if (!h) { printf("OpenProcess 失败\n"); return 2; }
    DWORD sz = 0;
    g_sdkBase = find_module(pid, "SecurityGuardSDK64.dll", &sz);
    g_sdkEnd = g_sdkBase + sz;

    ULONG_PTR obj = 0x23649a3e000ULL;
    if (argc >= 2) obj = (ULONG_PTR)_strtoui64(argv[1], NULL, 0);

    printf("PID=%lu SDK=%p\n对象 @ 0x%llx\n\n", pid, (void *)g_sdkBase, (unsigned long long)obj);

    /* 读大一点，看清全貌 */
    unsigned char buf[512];
    SIZE_T got = 0;
    if (!ReadProcessMemory(h, (LPCVOID)obj, buf, sizeof(buf), &got)) {
        printf("读取失败 %lu\n", GetLastError());
        return 3;
    }
    printf("[对象字段 %llu 字节]\n", (unsigned long long)got);
    for (int off = 0; off + 8 <= (int)got; off += 8) {
        field(h, obj, off, buf);
        printf("\n");
    }

    /* 把对象里明显的字符串指针展开 */
    printf("\n[指针展开]\n");
    for (int off = 0; off + 8 <= 160; off += 8) {
        ULONG_PTR v;
        memcpy(&v, buf + off, 8);
        if (!v || (v >= g_sdkBase && v < g_sdkEnd)) continue;
        if (!readable(h, v, 8)) continue;
        unsigned char sub[144];
        SIZE_T sg = 0;
        if (!ReadProcessMemory(h, (LPCVOID)v, sub, sizeof(sub), &sg)) continue;
        /* 判断 sub 里是否有可打印串 */
        int printable = 0;
        for (SIZE_T i = 0; i < sg && i < 40; i++)
            if (sub[i] >= 0x20 && sub[i] < 0x7f) printable++; else break;
        if (printable < 8) continue;

        printf("\n  +0x%02x → 0x%llx:\n", off, (unsigned long long)v);
        for (int k = 0; k < 10; k++) {
            ULONG_PTR vv; memcpy(&vv, sub + k * 8, 8);
            printf("     [%d] ", k);
            field(h, v, k * 8, sub);
            printf("\n");
        }
    }

    CloseHandle(h);
    return 0;
}
