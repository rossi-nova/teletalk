/**
 * 在钉钉进程内存中搜索 vmsign 配置 GUID
 *
 * 目标 GUID: 3be229e1-301d-4639-b88a-16997824d71b
 * 若 SDK 已拉取过配置，该 GUID 应出现在内存里（字符串或二进制形式）。
 *
 * 编译：cl /nologo /O2 /Fe:grep-guid.exe grep-guid.c advapi32.lib Psapi.lib
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

static int search_all(HANDLE h, const unsigned char *needle, size_t nlen, const char *label, int maxHits) {
    const SIZE_T CHUNK = 1 << 20;
    unsigned char *buf = (unsigned char *)malloc(CHUNK + nlen);
    if (!buf) return 0;
    int hits = 0;
    MEMORY_BASIC_INFORMATION mbi;
    ULONG_PTR a = 0;

    printf("\n== %s (%zu 字节) ==\n", label, nlen);

    while (VirtualQueryEx(h, (LPCVOID)a, &mbi, sizeof(mbi)) && hits < maxHits) {
        if (mbi.State == MEM_COMMIT &&
            (mbi.Protect == PAGE_READWRITE || mbi.Protect == PAGE_READONLY ||
             mbi.Protect == PAGE_WRITECOPY || mbi.Protect == PAGE_EXECUTE_READWRITE)) {
            ULONG_PTR rs = (ULONG_PTR)mbi.BaseAddress, re = rs + mbi.RegionSize;
            for (ULONG_PTR q = rs; q < re && hits < maxHits; q += CHUNK) {
                SIZE_T want = (SIZE_T)((re - q) < CHUNK ? (re - q) : CHUNK);
                SIZE_T got = 0;
                if (!ReadProcessMemory(h, (LPCVOID)q, buf, want, &got) || got < nlen) continue;
                for (SIZE_T i = 0; i + nlen <= got && hits < maxHits; i++) {
                    if (buf[i] != needle[0]) continue;
                    if (memcmp(buf + i, needle, nlen) == 0) {
                        printf("  命中 @ 0x%llx", (unsigned long long)(q + i));
                        /* 打印前后 96 字节 */
                        int s = (int)i - 24; if (s < 0) s = 0;
                        SIZE_T e = i + nlen + 72; if (e > got) e = got;
                        printf("\n    前文: ");
                        for (SIZE_T k = s; k < i; k++) {
                            unsigned char c = buf[k];
                            putchar((c >= 0x20 && c < 0x7f) ? c : '.');
                        }
                        printf("\n    后文: ");
                        for (SIZE_T k = i + nlen; k < e; k++) {
                            unsigned char c = buf[k];
                            putchar((c >= 0x20 && c < 0x7f) ? c : '.');
                        }
                        printf("\n");
                        hits++;
                        i += nlen - 1;
                    }
                }
            }
        }
        a = (ULONG_PTR)mbi.BaseAddress + mbi.RegionSize;
        if (a < (ULONG_PTR)mbi.BaseAddress) break;
    }
    if (!hits) printf("  未找到\n");
    free(buf);
    return hits;
}

int main(void) {
    SetConsoleOutputCP(CP_UTF8);
    printf("=== vmsign GUID 内存搜索 ===\n");

    DWORD pid = find_pid();
    if (!pid) { printf("DingTalk not found\n"); return 1; }
    HANDLE h = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, pid);
    if (!h) { printf("OpenProcess failed: %lu\n", GetLastError()); return 2; }
    printf("PID=%lu\n", pid);

    /* 形式 1：字符串 */
    const char *s1 = "3be229e1-301d-4639-b88a-16997824d71b";
    search_all(h, (const unsigned char *)s1, strlen(s1), "字符串形式", 5);

    /* 形式 2：大写 */
    const char *s2 = "3BE229E1-301D-4639-B88A-16997824D71B";
    search_all(h, (const unsigned char *)s2, strlen(s2), "大写形式", 3);

    /* 形式 3：二进制 GUID（小端布局） */
    unsigned char g[16] = {
        0xe1, 0x29, 0xe2, 0x3b,   /* Data1 小端 */
        0x1d, 0x30,               /* Data2 */
        0x39, 0x46,               /* Data3 */
        0xb8, 0x8a,               /* Data4[0..1] */
        0x16, 0x99, 0x78, 0x24, 0xd7, 0x1b
    };
    search_all(h, g, 16, "二进制 GUID", 5);

    /* 形式 4：只有前 8 位 */
    const char *s4 = "3be229e1";
    search_all(h, (const unsigned char *)s4, strlen(s4), "前缀 3be229e1", 3);

    CloseHandle(h);
    return 0;
}