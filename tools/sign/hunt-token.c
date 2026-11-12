/**
 * 从已知真 token 反推 SDK 的签名输出缓冲区
 *
 * 已知（抓包）：
 *   x5-sign:  wzMK2c002xAALVaBW9Hwl2Cjiij2nVaNXE95q/tS5pZ/GfqdWL3qbjc5jK+bNeTPHtTGk7xb7fm1x5KJBddS6QHItT1WnVaNVp1WjV
 *   x5-miniwua: BcAtBdBTkSxT10Kb4xIDR+eKbp+CKjvPU2xROzpxb5JIRLju/x2uyJZ157+r2DUTCXc7...
 *   x5-umid-token: P1gA-QzoVB1hY24XQpGHOcHpox5U4Ci1ZeIC8LCyNyluyzB8P0Z5Ila7ikS45WU65dSjbEsvBSPeVhfG3gE_zQZK
 *
 * 在进程内存中搜索这些串的前缀。若 SDK 已在本进程生成过签名，应能命中。
 *
 * 编译：cl /nologo /O2 /Fe:hunt-token.exe hunt-token.c advapi32.lib Psapi.lib
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

typedef struct { const char *needle; const char *label; } TPATTERN;

static TPATTERN g_patterns[] = {
    { "wzMK2c002",        "x5-sign 前缀" },
    { "BcAtBdBT",         "x5-miniwua 前缀" },
    { "P1gA-Qzo",         "x5-umid-token 前缀" },
    { "pc_1.0.70.1028_0", "x5-bx-version（版本串）" },
    { "x5-sign",          "头名" },
    { "x5-miniwua",       "头名" },
    { "getSecurityToken", "函数名" },
};
#define TNPAT (sizeof(g_patterns)/sizeof(g_patterns[0]))

int main(void) {
    SetConsoleOutputCP(CP_UTF8);
    printf("=== 真 token 特征搜索 ===\n");

    DWORD pid = find_pid();
    HANDLE h = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, pid);
    if (!h) { printf("OpenProcess 失败 %lu\n", GetLastError()); return 2; }
    printf("PID=%lu\n\n", pid);

    const SIZE_T CHUNK = 1 << 20;
    unsigned char *buf = (unsigned char *)malloc(CHUNK);
    if (!buf) return 3;

    int hits[TNPAT];
    memset(hits, 0, sizeof(hits));
    ULONG_PTR firstAt[TNPAT];
    memset(firstAt, 0, sizeof(firstAt));

    MEMORY_BASIC_INFORMATION mbi;
    ULONG_PTR addr = 0;

    while (VirtualQueryEx(h, (LPCVOID)addr, &mbi, sizeof(mbi))) {
        if (mbi.State == MEM_COMMIT &&
            (mbi.Protect == PAGE_READWRITE || mbi.Protect == PAGE_READONLY ||
             mbi.Protect == PAGE_WRITECOPY || mbi.Protect == PAGE_EXECUTE_READWRITE)) {
            ULONG_PTR rs = (ULONG_PTR)mbi.BaseAddress, re = rs + mbi.RegionSize;
            for (ULONG_PTR q = rs; q < re; q += CHUNK) {
                SIZE_T want = (SIZE_T)((re - q) < CHUNK ? (re - q) : CHUNK);
                SIZE_T got = 0;
                if (!ReadProcessMemory(h, (LPCVOID)q, buf, want, &got)) continue;

                for (size_t p = 0; p < TNPAT; p++) {
                    size_t nlen = strlen(g_patterns[p].needle);
                    if (got < nlen) continue;
                    const unsigned char *f = NULL;
                    /* 简单 memmem */
                    for (SIZE_T i = 0; i + nlen <= got; i++) {
                        if (buf[i] == (unsigned char)g_patterns[p].needle[0] &&
                            memcmp(buf + i, g_patterns[p].needle, nlen) == 0) { f = buf + i;
                            if (!firstAt[p]) firstAt[p] = q + i;
                            hits[p]++; break; }
                    }
                }
            }
        }
        addr = (ULONG_PTR)mbi.BaseAddress + mbi.RegionSize;
        if (addr < (ULONG_PTR)mbi.BaseAddress) break;
    }

    printf("== 结果 ==\n");
    for (size_t p = 0; p < TNPAT; p++) {
        printf("  %-24s hits=%d", g_patterns[p].label, hits[p]);
        if (firstAt[p]) printf(", first @ 0x%llx", (unsigned long long)firstAt[p]);
        printf("\n");
    }

    /* 对命中的真 token 前缀，打印上下文 */
    if (firstAt[0]) {
        char ctx[200] = {0};
        SIZE_T g = 0;
        ULONG_PTR a = firstAt[0] > 40 ? firstAt[0] - 40 : firstAt[0];
        if (ReadProcessMemory(h, (LPCVOID)a, ctx, sizeof(ctx) - 1, &g) && g > 0) {
            printf("\n[x5-sign 前缀上下文 @ 0x%llx]\n  ", (unsigned long long)a);
            for (SIZE_T i = 0; i < g; i++) {
                unsigned char c = (unsigned char)ctx[i];
                putchar((c >= 0x20 && c < 0x7f) ? c : '.');
            }
            printf("\n");
        }
    }

    free(buf);
    CloseHandle(h);
    return 0;
}
