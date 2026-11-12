/**
 * 直接从钉钉进程内存提取 oauth token 与设备 ID
 *
 * 原理：登录后 token 会以 "oauth_k1:" 开头留在内存里。
 * 比 MITM 抓包简单得多，也不需要 Clash 规则。
 *
 * 编译：cl /nologo /O2 /Fe:grab-token.exe grab-token.c advapi32.lib Psapi.lib
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

static int is_tok_char(unsigned char c) {
    return (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') ||
           (c >= '0' && c <= '9') || c == '+' || c == '/' || c == '=' || c == '_' || c == '-';
}

int main(void) {
    SetConsoleOutputCP(CP_UTF8);
    fprintf(stderr, "=== 提取 oauth token ===\n");

    DWORD pid = find_pid();
    if (!pid) { fprintf(stderr, "DingTalk not found\n"); return 1; }
    fprintf(stderr, "PID=%lu\n", pid);

    HANDLE h = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, pid);
    if (!h) { fprintf(stderr, "OpenProcess failed %lu\n", GetLastError()); return 2; }

    const char *needle = "oauth_k1:";
    size_t nlen = strlen(needle);
    const SIZE_T CHUNK = 1 << 20;
    unsigned char *buf = (unsigned char *)malloc(CHUNK);

    char bestToken[1024] = {0};
    size_t bestLen = 0;
    char bestDid[64] = {0};

    MEMORY_BASIC_INFORMATION mbi;
    ULONG_PTR a = 0;
    int found = 0;

    while (VirtualQueryEx(h, (LPCVOID)a, &mbi, sizeof(mbi)) && found < 20) {
        if (mbi.State == MEM_COMMIT &&
            (mbi.Protect == PAGE_READWRITE || mbi.Protect == PAGE_READONLY ||
             mbi.Protect == PAGE_WRITECOPY || mbi.Protect == PAGE_EXECUTE_READWRITE)) {
            ULONG_PTR rs = (ULONG_PTR)mbi.BaseAddress, re = rs + mbi.RegionSize;
            for (ULONG_PTR q = rs; q < re && found < 20; q += CHUNK) {
                SIZE_T want = (SIZE_T)((re - q) < CHUNK ? (re - q) : CHUNK);
                SIZE_T got = 0;
                if (!ReadProcessMemory(h, (LPCVOID)q, buf, want, &got) || got < nlen) continue;

                for (SIZE_T i = 0; i + nlen <= got && found < 20; i++) {
                    if (buf[i] != (unsigned char)needle[0]) continue;
                    if (memcmp(buf + i, needle, nlen) != 0) continue;

                    SIZE_T j = i + nlen;
                    while (j < got && j - i < 1000 && is_tok_char(buf[j])) j++;
                    SIZE_T tl = j - i;
                    if (tl < 40) continue;

                    fprintf(stderr, "\n[token] 0x%llx  len=%zu\n",
                            (unsigned long long)(q + i), tl);
                    fprintf(stderr, "  %.120s...\n", buf + i);

                    if (tl > bestLen) {
                        memcpy(bestToken, buf + i, tl);
                        bestToken[tl] = 0;
                        bestLen = tl;
                    }

                    /* 找附近的 did（32 位 hex） */
                    int s = (int)i - 400; if (s < 0) s = 0;
                    SIZE_T e = i + tl + 400; if (e > got) e = got;
                    for (SIZE_T k = (SIZE_T)s; k + 32 < e && !bestDid[0]; k++) {
                        int hex = 1;
                        for (int m = 0; m < 32; m++) {
                            unsigned char c = buf[k + m];
                            if (!((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f'))) { hex = 0; break; }
                        }
                        if (hex) {
                            memcpy(bestDid, buf + k, 32);
                            bestDid[32] = 0;
                            fprintf(stderr, "  附近 did 候选: %s\n", bestDid);
                        }
                    }
                    found++;
                    i = j;
                }
            }
        }
        a = (ULONG_PTR)mbi.BaseAddress + mbi.RegionSize;
        if (a < (ULONG_PTR)mbi.BaseAddress) break;
    }

    /* 输出 JSON 到 stdout（供脚本消费） */
    printf("{\"pid\":%lu,\"token\":\"%s\",\"did\":\"%s\"}\n", pid, bestToken, bestDid);

    free(buf);
    CloseHandle(h);
    return bestLen ? 0 : 4;
}