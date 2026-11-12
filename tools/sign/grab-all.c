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
    char token_frame[1024] = {0};
    char token_bare[1024] = {0};
    char did[128] = {0};
    char did_fb[128] = {0};
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
                    /* token：同时收集两种格式，结尾优先帧头格式（当前连接在用） */
                    if (!token_frame[0] && i + 16 <= got && buf[i] == 't' &&
                        memcmp(buf + i, "token:oauth_k1:", 15) == 0) {
                        SIZE_T j = i + 15;
                        while (j < got && j - i < 1000 && tok_char(buf[j])) j++;
                        if (j - i >= 90) {
                            memcpy(token_frame, buf + i + 6, j - i - 6);
                            token_frame[j - i - 6] = 0;
                            fprintf(stderr, "[token:frame] %s\n", token_frame);
                        }
                    }
                    if (!token_bare[0] && buf[i] == 'o' && i + 9 <= got &&
                        memcmp(buf + i, "oauth_k1:", 9) == 0 &&
                        !(i > 0 && buf[i - 1] == 't')) {
                        SIZE_T j = i + 9;
                        while (j < got && j - i < 1000 && tok_char(buf[j])) j++;
                        if (j - i >= 90) {
                            memcpy(token_bare, buf + i, j - i);
                            token_bare[j - i] = 0;
                            fprintf(stderr, "[token:bare] %s\n", token_bare);
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
                    /* did：帧内 "did:<32hex>"（前面是 cs-idx-ver:0）。 */
                    /* XMP 干扰项全大写；日志里的 did 后跟 umid_token。 */
                    if (!did[0] && i + 36 <= got && buf[i] == 'd' &&
                        memcmp(buf + i, "did:", 4) == 0 &&
                        buf[i + 4] >= 'a' && buf[i + 4] <= 'f') {
                        int ok = 1;
                        for (int m = 1; m < 32; m++) {
                            unsigned char c = buf[i + 4 + m];
                            if (!((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f'))) { ok = 0; break; }
                        }
                        if (ok) {
                            int inFrame = (i >= 13 && memcmp(buf + i - 13, "cs-idx-ver:0", 12) == 0);
                            if (inFrame) {
                                memcpy(did, buf + i + 4, 32); did[32] = 0;
                                fprintf(stderr, "[did:frame] %s\n", did);
                            } else if (!did_fb[0]) {
                                memcpy(did_fb, buf + i + 4, 32); did_fb[32] = 0;
                            }
                        }
                    }
                }
            }
        }
        a = (ULONG_PTR)mbi.BaseAddress + mbi.RegionSize;
        if (a < (ULONG_PTR)mbi.BaseAddress) break;
    }

    if (token_frame[0]) { strcpy(token, token_frame); fprintf(stderr, "[token] use frame\n");}
    else if (token_bare[0]) { strcpy(token, token_bare); fprintf(stderr, "[token] use bare\n");}
    if (!did[0] && did_fb[0]) { memcpy(did, did_fb, 33); fprintf(stderr, "[did:fb] %s\n", did_fb); }
    printf("{\"pid\":%lu,\"token\":\"%s\",\"did\":\"%s\",\"x5sign\":\"%s\",\"orgId\":\"%s\"}\n",
           pid, token, did, x5sign, org);

    free(buf);
    CloseHandle(h);
    return token[0] ? 0 : 4;
}