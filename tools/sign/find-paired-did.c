/**
 * 从进程内存找与 token 配对的 did
 *
 * 判据：LWP 的 /reg 请求头里 token 与 did 相邻（同一块内存）。
 * 搜索 "token" 和 "did" 同时出现的内存块，提取 did 值。
 *
 * 编译：cl /nologo /O2 /Fe:find-paired-did.exe find-paired-did.c advapi32.lib Psapi.lib
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

static int is_hex(char c) {
    return (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f');
}

int main(void) {
    SetConsoleOutputCP(CP_UTF8);
    fprintf(stderr, "=== 找配对的 did ===\n");

    DWORD pid = find_pid();
    HANDLE h = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, pid);
    if (!h) { fprintf(stderr, "OpenProcess %lu\n", GetLastError()); return 2; }

    const SIZE_T CHUNK = 1 << 20;
    unsigned char *buf = (unsigned char *)malloc(CHUNK);

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

                /* 找 "did:" 后跟 32 位 hex 的模式（LWP header 格式） */
                for (SIZE_T i = 0; i + 40 <= got; i++) {
                    if (buf[i] != 'd' || i + 4 >= got) continue;
                    if (memcmp(buf + i, "did:", 4) == 0) {
                        SIZE_T j = i + 4;
                        if (j + 32 <= got && is_hex(buf[j])) {
                            int ok = 1;
                            for (int m = 1; m < 32; m++) if (!is_hex(buf[j + m])) { ok = 0; break; }
                            if (ok) {
                                char did[33] = {0};
                                memcpy(did, buf + j, 32);
                                /* 打印上下文，看是否和 token 在一起 */
                                int ctxTok = 0;
                                SIZE_T s = i > 600 ? i - 600 : 0;
                                SIZE_T e = i + 100 < got ? i + 100 : got;
                                for (SIZE_T k = s; k + 9 < e; k++) {
                                    if (memcmp(buf + k, "oauth_k1:", 9) == 0) { ctxTok = 1; break; }
                                }
                                fprintf(stderr, "[did:格式] %s  @0x%llx  附近有token=%d\n",
                                        did, (unsigned long long)(q + i), ctxTok);
                            }
                        }
                    }
                }
            }
        }
        a = (ULONG_PTR)mbi.BaseAddress + mbi.RegionSize;
        if (a < (ULONG_PTR)mbi.BaseAddress) break;
    }

    free(buf);
    CloseHandle(h);
    return 0;
}