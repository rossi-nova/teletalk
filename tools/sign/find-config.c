/**
 * 搜索钉钉进程堆中的 vmsign 配置内容
 *
 * 思路：配置内容可能是 JSON / protobuf / 自定义二进制，
 * 但一定包含特征串（"vmsign"、"sign_br"、"SignBox" 等）。
 *
 * 编译：cl /nologo /O2 /Fe:find-config.exe find-config.c advapi32.lib Psapi.lib
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
            HANDLE h = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pe.dwSize ? pe.th32ProcessID : 0);
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

static int contains(const unsigned char *hay, size_t hlen, const char *needle) {
    size_t n = strlen(needle);
    if (hlen < n) return 0;
    for (size_t i = 0; i + n <= hlen; i++) {
        if (hay[i] == (unsigned char)needle[0] && memcmp(hay + i, needle, n) == 0) return 1;
    }
    return 0;
}

int main(void) {
    SetConsoleOutputCP(CP_UTF8);
    printf("=== vmsign 配置内容搜索 ===\n");

    DWORD pid = find_pid();
    if (!pid) { printf("DingTalk not found\n"); return 1; }
    HANDLE h = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, pid);
    if (!h) { printf("OpenProcess failed %lu\n", GetLastError()); return 2; }
    DWORD sz = 0;
    ULONG_PTR sdk = find_module(pid, "SecurityGuardSDK64.dll", &sz);
    printf("PID=%lu SDK=%p size=0x%x\n\n", pid, (void *)sdk, sz);

    /* 特征词 */
    const char *keys[] = {
        "vmsign", "VMSign", "sign_br", "SignBR", "SignBox",
        "sign_config", "static_sign", "dynamic_sign",
    };
    const int nkeys = sizeof(keys) / sizeof(keys[0]);

    const SIZE_T CHUNK = 1 << 20;
    unsigned char *buf = (unsigned char *)malloc(CHUNK);
    MEMORY_BASIC_INFORMATION mbi;
    ULONG_PTR a = 0;
    int found = 0;

    printf("== 扫描堆区域（排除 SDK 自身映像）==\n");
    while (VirtualQueryEx(h, (LPCVOID)a, &mbi, sizeof(mbi)) && found < 30) {
        ULONG_PTR rs = (ULONG_PTR)mbi.BaseAddress;
        if (mbi.State == MEM_COMMIT &&
            (mbi.Protect == PAGE_READWRITE || mbi.Protect == PAGE_WRITECOPY) &&
            !(rs >= sdk && rs < sdk + sz)) {   /* 跳过 SDK 映像 */
            ULONG_PTR re = rs + mbi.RegionSize;
            for (ULONG_PTR q = rs; q < re && found < 30; q += CHUNK) {
                SIZE_T want = (SIZE_T)((re - q) < CHUNK ? (re - q) : CHUNK);
                SIZE_T got = 0;
                if (!ReadProcessMemory(h, (LPCVOID)q, buf, want, &got)) continue;

                for (int k = 0; k < nkeys; k++) {
                    size_t n = strlen(keys[k]);
                    for (SIZE_T i = 0; i + n <= got; i++) {
                        if (buf[i] == (unsigned char)keys[k][0] && memcmp(buf + i, keys[k], n) == 0) {
                            printf("\n[%s] @ 0x%llx\n", keys[k], (unsigned long long)(q + i));
                            int s = (int)i - 32; if (s < 0) s = 0;
                            SIZE_T e = i + n + 96; if (e > got) e = got;
                            printf("  ");
                            for (SIZE_T j = (SIZE_T)s; j < e; j++) {
                                unsigned char c = buf[j];
                                putchar((c >= 0x20 && c < 0x7f) ? c : '.');
                            }
                            printf("\n");
                            found++;
                            if (found >= 30) break;
                            i += n;
                        }
                    }
                    if (found >= 30) break;
                }
            }
        }
        a = (ULONG_PTR)mbi.BaseAddress + mbi.RegionSize;
        if (a < (ULONG_PTR)mbi.BaseAddress) break;
    }

    printf("\n共 %d 处\n", found);
    free(buf);
    CloseHandle(h);
    return 0;
}