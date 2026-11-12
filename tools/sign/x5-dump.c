/**
 * 提取 SDK 实时生成的 x5-sign
 *
 * 已确认 SDK 在钉钉进程内生成 x5-sign（前缀 wzMK2c002xA），
 * 定位方式：搜索 "wzMK2c002" 特征串，提取完整值。
 *
 * 用法：x5-dump [--json]
 *
 * 编译：cl /nologo /O2 /Fe:x5-dump.exe x5-dump.c advapi32.lib Psapi.lib
 */
#include <windows.h>
#include <stdio.h>
#include <tlhelp32.h>
#include <psapi.h>
#include <string.h>

#define MAX_TOKENS 16
#define TOKEN_MAX  2048

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

static int is_b64(unsigned char c) {
    return (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') ||
           (c >= '0' && c <= '9') || c == '+' || c == '/' || c == '=' ||
           c == '-' || c == '_';
}

int main(int argc, char **argv) {
    SetConsoleOutputCP(CP_UTF8);
    int json = (argc > 1 && strcmp(argv[1], "--json") == 0);

    DWORD pid = find_pid();
    if (!pid) { fprintf(stderr, "DingTalk.exe not found\n"); return 1; }
    HANDLE h = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, pid);
    if (!h) { fprintf(stderr, "OpenProcess failed: %lu\n", GetLastError()); return 2; }

    const char *needle = "wzMK2c002";
    size_t nlen = strlen(needle);
    const SIZE_T CHUNK = 1 << 20;
    unsigned char *buf = (unsigned char *)malloc(CHUNK);
    if (!buf) return 3;

    char tokens[MAX_TOKENS][TOKEN_MAX];
    ULONG_PTR tokenAddr[MAX_TOKENS];
    int nt = 0;

    MEMORY_BASIC_INFORMATION mbi;
    ULONG_PTR addr = 0;

    while (VirtualQueryEx(h, (LPCVOID)addr, &mbi, sizeof(mbi)) && nt < MAX_TOKENS) {
        if (mbi.State == MEM_COMMIT &&
            (mbi.Protect == PAGE_READWRITE || mbi.Protect == PAGE_READONLY ||
             mbi.Protect == PAGE_WRITECOPY || mbi.Protect == PAGE_EXECUTE_READWRITE)) {
            ULONG_PTR rs = (ULONG_PTR)mbi.BaseAddress, re = rs + mbi.RegionSize;
            for (ULONG_PTR q = rs; q < re && nt < MAX_TOKENS; q += CHUNK) {
                SIZE_T want = (SIZE_T)((re - q) < CHUNK ? (re - q) : CHUNK);
                SIZE_T got = 0;
                if (!ReadProcessMemory(h, (LPCVOID)q, buf, want, &got) || got < nlen) continue;
                for (SIZE_T i = 0; i + nlen <= got && nt < MAX_TOKENS; i++) {
                    if (buf[i] != (unsigned char)needle[0]) continue;
                    if (memcmp(buf + i, needle, nlen) != 0) continue;
                    /* 提取到非 base64 字符为止 */
                    SIZE_T j = i;
                    while (j < got && j - i < TOKEN_MAX - 1 && is_b64(buf[j])) j++;
                    SIZE_T len = j - i;
                    if (len < 40) { i = j; continue; }
                    memcpy(tokens[nt], buf + i, len);
                    tokens[nt][len] = 0;
                    tokenAddr[nt] = q + i;
                    nt++;
                    i = j;
                }
            }
        }
        addr = (ULONG_PTR)mbi.BaseAddress + mbi.RegionSize;
        if (addr < (ULONG_PTR)mbi.BaseAddress) break;
    }

    if (json) {
        printf("{\"pid\":%lu,\"tokens\":[", pid);
        for (int i = 0; i < nt; i++) {
            printf("%s{\"addr\":\"0x%llx\",\"len\":%zu,\"value\":\"%s\"}",
                   i ? "," : "", (unsigned long long)tokenAddr[i],
                   strlen(tokens[i]), tokens[i]);
        }
        printf("]}\n");
    } else {
        printf("PID=%lu  x5-sign 候选 %d 个\n\n", pid, nt);
        for (int i = 0; i < nt; i++) {
            printf("[%d] @ 0x%llx  len=%zu\n", i,
                   (unsigned long long)tokenAddr[i], strlen(tokens[i]));
            printf("    %s\n\n", tokens[i]);
        }
    }

    free(buf);
    CloseHandle(h);
    return nt ? 0 : 4;
}
