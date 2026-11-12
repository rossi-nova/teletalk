/**
 * token 候选分析：解码 base64、分析结构、反查持有对象
 *
 * 已知可疑地址（PID 5668 本次运行）：
 *   0x2362c5e10d0 / 0x2362c5e12d1  ← 疑似 x5-sign
 *   0x2362c65d9b0 / 0x2362c65dbb1  ← 另一实例
 *
 * 编译：cl /nologo /O2 /Fe:token-analyze.exe token-analyze.c advapi32.lib Psapi.lib
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

static int b64val(char c) {
    if (c >= 'A' && c <= 'Z') return c - 'A';
    if (c >= 'a' && c <= 'z') return c - 'a' + 26;
    if (c >= '0' && c <= '9') return c - '0' + 52;
    if (c == '+' || c == '-') return 62;
    if (c == '/' || c == '_') return 63;
    return -1;
}

static int b64decode(const char *in, int inlen, unsigned char *out, int outcap) {
    int n = 0, acc = 0, bits = 0;
    for (int i = 0; i < inlen && n < outcap; i++) {
        if (in[i] == '=') break;
        int v = b64val(in[i]);
        if (v < 0) continue;
        acc = (acc << 6) | v;
        bits += 6;
        if (bits >= 8) { bits -= 8; out[n++] = (unsigned char)((acc >> bits) & 0xff); }
    }
    return n;
}

/** 找指向 addr 的指针（对象头反查） */
static ULONG_PTR find_referrer(HANDLE h, ULONG_PTR target, ULONG_PTR lo, ULONG_PTR hi) {
    const SIZE_T CHUNK = 1 << 20;
    unsigned char *buf = (unsigned char *)malloc(CHUNK);
    if (!buf) return 0;
    MEMORY_BASIC_INFORMATION mbi;
    ULONG_PTR a = lo;
    while (VirtualQueryEx(h, (LPCVOID)a, &mbi, sizeof(mbi)) && a < hi) {
        if (mbi.State == MEM_COMMIT &&
            (mbi.Protect == PAGE_READWRITE || mbi.Protect == PAGE_WRITECOPY)) {
            ULONG_PTR rs = (ULONG_PTR)mbi.BaseAddress, re = rs + mbi.RegionSize;
            for (ULONG_PTR q = rs; q < re; q += CHUNK) {
                SIZE_T want = (SIZE_T)((re - q) < CHUNK ? (re - q) : CHUNK);
                SIZE_T got = 0;
                if (!ReadProcessMemory(h, (LPCVOID)q, buf, want, &got) || got < 8) continue;
                for (SIZE_T i = 0; i + 8 <= got; i += 8) {
                    ULONG_PTR v; memcpy(&v, buf + i, 8);
                    if (v == target) { free(buf); return q + i; }
                }
            }
        }
        a = (ULONG_PTR)mbi.BaseAddress + mbi.RegionSize;
        if (a < (ULONG_PTR)mbi.BaseAddress) break;
    }
    free(buf);
    return 0;
}

int main(int argc, char **argv) {
    SetConsoleOutputCP(CP_UTF8);
    printf("=== token 候选分析 ===\n");

    DWORD pid = find_pid();
    HANDLE h = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, pid);
    if (!h) { printf("OpenProcess 失败 %lu\n", GetLastError()); return 2; }
    printf("PID=%lu\n", pid);

    /* 目标地址（可通过命令行覆盖） */
    ULONG_PTR targets[8];
    int nt = 0;
    for (int i = 1; i < argc && nt < 8; i++) targets[nt++] = (ULONG_PTR)_strtoui64(argv[i], NULL, 0);

    if (!nt) {
        targets[nt++] = 0x2362c5e10d0;
        targets[nt++] = 0x2362c65d9b0;
    }

    for (int t = 0; t < nt; t++) {
        ULONG_PTR addr = targets[t];
        char s[1100] = {0};
        SIZE_T got = 0;
        printf("\n=== 地址 0x%llx ===\n", (unsigned long long)addr);
        if (!ReadProcessMemory(h, (LPCVOID)addr, s, 1024, &got) || got < 16) {
            printf("  读取失败\n"); continue;
        }
        s[got] = 0;

        /* 找到串长 */
        int len = 0;
        while (len < (int)got && b64val(s[len]) >= 0) len++;
        printf("  长度: %d\n", len);
        printf("  内容: %.120s%s\n", s, len > 120 ? "..." : "");

        unsigned char dec[800];
        int dn = b64decode(s, len, dec, sizeof(dec));
        printf("  解码后 %d 字节: ", dn);
        for (int i = 0; i < dn && i < 40; i++) printf("%02x ", dec[i]);
        printf("\n");
        printf("  解码 ascii: ");
        for (int i = 0; i < dn && i < 40; i++) {
            unsigned char c = dec[i];
            putchar((c >= 0x20 && c < 0x7f) ? c : '.');
        }
        printf("\n");

        /* 反查持有者 */
        ULONG_PTR ref = find_referrer(h, addr, 0x10000, (ULONG_PTR)1 << 47);
        if (ref) {
            printf("  ← 被 0x%llx 引用\n", (unsigned long long)ref);
            /* 读引用点周围的 64 字节（对象字段） */
            ULONG_PTR objStart = ref & ~(ULONG_PTR)0xf;
            unsigned char ctx[128];
            SIZE_T cg = 0;
            if (ReadProcessMemory(h, (LPCVOID)(objStart - 32), ctx, sizeof(ctx), &cg)) {
                printf("  [对象上下文 0x%llx]\n", (unsigned long long)(objStart - 32));
                for (int k = 0; k < 8; k++) {
                    ULONG_PTR v; memcpy(&v, ctx + k * 8, 8);
                    printf("     [%d] 0x%016llx\n", k, (unsigned long long)v);
                }
            }
        } else {
            printf("  ← 无引用（可能是栈/临时）\n");
        }
    }

    CloseHandle(h);
    return 0;
}
