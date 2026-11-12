/**
 * 从 x5-sign 缓存地址反查 SDK 的内部对象
 *
 * 思路：token 存在某个对象的 std::string 成员里（SSO 布局：ptr,size,cap）。
 * 找到引用该 token 指针的对象后，打印它的完整字段布局，
 * 定位其中的签名状态（factors、时间戳、计数器）。
 *
 * 编译：cl /nologo /O2 /Fe:rev-object.exe rev-object.c advapi32.lib Psapi.lib
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
        if (_stricmp(me.szModule, name) == 0) {
            base = (ULONG_PTR)me.modBaseAddr; if (sz) *sz = me.modBaseSize; break;
        }
    } while (Module32Next(snap, &me));
    CloseHandle(snap);
    return base;
}

static ULONG_PTR g_sdkBase, g_sdkEnd;

static void show_ptr(HANDLE h, ULONG_PTR v) {
    if (!v) { printf("NULL"); return; }
    if (v >= g_sdkBase && v < g_sdkEnd) {
        printf("SDK+0x%llx", (unsigned long long)(v - g_sdkBase));
        return;
    }
    printf("0x%llx", (unsigned long long)v);
    /* 试着读成 ASCII */
    char s[64] = {0};
    SIZE_T g = 0;
    if (v > 0x10000 && ReadProcessMemory(h, (LPCVOID)v, s, sizeof(s) - 1, &g) && g > 3) {
        int pr = 0;
        for (SIZE_T i = 0; i < g && i < 40; i++) {
            if (s[i] >= 0x20 && s[i] < 0x7f) pr++; else break;
        }
        if (pr >= 5) printf(" \"%.40s\"", s);
    }
}

/** 找所有指向 target 的指针位置 */
static void find_all_refs(HANDLE h, ULONG_PTR target, int maxOut) {
    const SIZE_T CHUNK = 1 << 20;
    unsigned char *buf = (unsigned char *)malloc(CHUNK);
    MEMORY_BASIC_INFORMATION mbi;
    ULONG_PTR a = 0;
    int n = 0;
    while (VirtualQueryEx(h, (LPCVOID)a, &mbi, sizeof(mbi)) && n < maxOut) {
        if (mbi.State == MEM_COMMIT &&
            (mbi.Protect == PAGE_READWRITE || mbi.Protect == PAGE_WRITECOPY)) {
            ULONG_PTR rs = (ULONG_PTR)mbi.BaseAddress, re = rs + mbi.RegionSize;
            for (ULONG_PTR q = rs; q < re && n < maxOut; q += CHUNK) {
                SIZE_T want = (SIZE_T)((re - q) < CHUNK ? (re - q) : CHUNK);
                SIZE_T got = 0;
                if (!ReadProcessMemory(h, (LPCVOID)q, buf, want, &got) || got < 8) continue;
                for (SIZE_T i = 0; i + 8 <= got; i += 8) {
                    ULONG_PTR v; memcpy(&v, buf + i, 8);
                    if (v == target) {
                        ULONG_PTR at = q + i;
                        printf("\n  [引用 #%d] @ 0x%llx", n + 1, (unsigned long long)at);
                        /* 判断是否 std::string 的 data 指针（后跟 size 与 cap） */
                        ULONG_PTR sz = 0, cap = 0;
                        ReadProcessMemory(h, (LPCVOID)(at + 8), &sz, 8, NULL);
                        ReadProcessMemory(h, (LPCVOID)(at + 16), &cap, 8, NULL);
                        if (sz > 0 && sz < 4096 && cap >= sz && cap < 65536)
                            printf("   [std::string: size=%llu cap=%llu]", (unsigned long long)sz, (unsigned long long)cap);
                        printf("\n");
                        /* 打印外层对象（-32..+64） */
                        ULONG_PTR obj = at - 32;
                        unsigned char ctx[160];
                        SIZE_T cg = 0;
                        if (ReadProcessMemory(h, (LPCVOID)obj, ctx, sizeof(ctx), &cg)) {
                            printf("    对象 @ 0x%llx:\n", (unsigned long long)obj);
                            for (int k = 0; k < 16; k++) {
                                ULONG_PTR vv; memcpy(&vv, ctx + k * 8, 8);
                                printf("      +0x%02x  ", k * 8);
                                show_ptr(h, vv);
                                printf("\n");
                            }
                        }
                        n++;
                    }
                }
            }
        }
        a = (ULONG_PTR)mbi.BaseAddress + mbi.RegionSize;
        if (a < (ULONG_PTR)mbi.BaseAddress) break;
    }
    free(buf);
}

int main(int argc, char **argv) {
    SetConsoleOutputCP(CP_UTF8);
    printf("=== x5-sign 持有者反查 ===\n");

    DWORD pid = find_pid();
    HANDLE h = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, pid);
    if (!h) { printf("OpenProcess 失败 %lu\n", GetLastError()); return 2; }
    DWORD sz = 0;
    g_sdkBase = find_module(pid, "SecurityGuardSDK64.dll", &sz);
    g_sdkEnd = g_sdkBase + sz;
    printf("PID=%lu SDK=%p\n", pid, (void *)g_sdkBase);

    /* 目标：三个已知 token 地址 */
    ULONG_PTR targets[3] = { 0x2362c413780, 0x2363cd221b0, 0x2363eed7a50 };
    if (argc >= 2) { targets[0] = (ULONG_PTR)_strtoui64(argv[1], NULL, 0); }

    for (int t = 0; t < 3; t++) {
        char probe[8] = {0};
        SIZE_T g = 0;
        if (!ReadProcessMemory(h, (LPCVOID)targets[t], probe, 4, &g)) continue;
        printf("\n=== token @ 0x%llx (%.8s...) ===\n", (unsigned long long)targets[t], probe);
        find_all_refs(h, targets[t], 5);
    }

    CloseHandle(h);
    return 0;
}
