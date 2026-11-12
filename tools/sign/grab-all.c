/**
 * 一次性抓齐：token + deviceId + orgId + x5-sign
 *
 * 输出 JSON，供网关直接消费。
 *
 * 编译：cl /nologo /O2 /Fe:grab-all.exe grab-all.c advapi32.lib Psapi.lib
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

static int tok_char(unsigned char c) {
    return (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') ||
           (c >= '0' && c <= '9') || c == '+' || c == '/' || c == '=';
}

static int is_hex(char c) {
    return (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F');
}

int main(void) {
    SetConsoleOutputCP(CP_UTF8);
    fprintf(stderr, "=== grab-all ===\n");

    DWORD pid = find_pid();
    if (!pid) { fprintf(stderr, "no DingTalk\n"); return 1; }
    HANDLE h = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, pid);
    if (!h) { fprintf(stderr, "OpenProcess %lu\n", GetLastError()); return 2; }

    const SIZE_T CHUNK = 1 << 20;
    unsigned char *buf = (unsigned char *)malloc(CHUNK);

    char token[1024] = {0};
    char did[128] = {0};
    char org[64] = {0};
    char x5sign[512] = {0};

    MEMORY_BASIC_INFORMATION mbi;
    ULONG_PTR a = 0;

    while (VirtualQueryEx(h, (LPCVOID)a, &mbi, sizeof(mbi))) {
        if (mbi.State == MEM_COMMIT &&
            (mbi.Protect == PAGE_READWRITE || mbi.Protect == PAGE_READONLY ||
             mbi.Protect == PAGE_WRITECOPY || mbi.Protect == PAGE_EXECUTE_READWRITE)) {
            ULONG_PTR rs = (ULONG_PTR)mbi.BaseAddress, re = rs + mbi.RegionSize;
            for (ULONG_PTR q = rs; q < re; q += CHUNK) {
                SIZE_T want = (SIZE_T)((re - q) < CHUNK ? (re - q) : CHUNK);
                SIZE_T got = 0;
                if (!ReadProcessMemory(h, (LPCVOID)q, buf, want, &got)) continue;

                for (SIZE_T i = 0; i + 16 <= got; i++) {
                    /* token */
                    if (!token[0] && buf[i] == 'o' &&
                        memcmp(buf + i, "oauth_k1:", 9) == 0) {
                        SIZE_T j = i + 9;
                        while (j < got && j - i < 1000 && tok_char(buf[j])) j++;
                        if (j - i >= 90) {
                            memcpy(token, buf + i, j - i);
                            token[j - i] = 0;
                            fprintf(stderr, "[token] len=%zu\n", j - i);
                        }
                    }
                    /* x5-sign */
                    if (!x5sign[0] && buf[i] == 'w' && i + 10 <= got &&
                        memcmp(buf + i, "wzMK2c002", 9) == 0) {
                        SIZE_T j = i;
                        while (j < got && j - i < 500 && tok_char(buf[j])) j++;
                        if (j - i >= 90) {
                            memcpy(x5sign, buf + i, j - i);
                            x5sign[j - i] = 0;
                            fprintf(stderr, "[x5-sign] len=%zu\n", j - i);
                        }
                    }
                    /* did: 32 位 hex，通常在 "did" 附近 */
                    if (!did[0] && i + 40 <= got && is_hex(buf[i])) {
                        int ok = 1;
                        for (int m = 1; m < 32; m++) if (!is_hex(buf[i + m])) { ok = 0; break; }
                        if (ok && (buf[i + 32] == 0 || buf[i + 32] == '"' || buf[i + 32] == ',')) {
                            /* 前后 100 字节内有 "did" 才认 */
                            SIZE_T s = i > 100 ? i - 100 : 0;
                            int ctx = 0;
                            for (SIZE_T k = s; k + 3 < i + 40 && k + 3 < got; k++) {
                                if (memcmp(buf + k, "did", 3) == 0) { ctx = 1; break; }
                            }
                            if (ctx) {
                                memcpy(did, buf + i, 32);
                                did[32] = 0;
                                fprintf(stderr, "[did] %s\n", did);
                            }
                        }
                    }
                }
            }
        }
        a = (ULONG_PTR)mbi.BaseAddress + mbi.RegionSize;
        if (a < (ULONG_PTR)mbi.BaseAddress) break;
    }

    printf("{\"pid\":%lu,\"token\":\"%s\",\"did\":\"%s\",\"x5sign\":\"%s\",\"orgId\":\"%s\"}\n",
           pid, token, did, x5sign, org);

    free(buf);
    CloseHandle(h);
    return token[0] ? 0 : 4;
}