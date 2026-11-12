/**
 * 追踪 vmsign GUID 缓冲区（SDK+0xA2A281）的使用者
 *
 * 已确认：
 *   - SDK RVA 0xA2A281 是解密输出缓冲区
 *   - 钉钉进程运行时此处为 "3be229e1-301d-4639-b88a-16997824d71b"
 *
 * 目标：找指向该地址的指针（= 谁在用它）
 *
 * 编译：cl /nologo /O2 /Fe:trace-guid.exe trace-guid.c advapi32.lib Psapi.lib
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
        if (_stricmp(me.szModule, name) == 0) { base = (ULONG_PTR)me.modBaseAddr; if (sz) *sz = me.modBaseSize; break; }
    } while (Module32Next(snap, &me));
    CloseHandle(snap);
    return base;
}

int main(void) {
    SetConsoleOutputCP(CP_UTF8);
    printf("=== vmsign GUID 缓冲区追踪 ===\n");

    DWORD pid = find_pid();
    HANDLE h = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, pid);
    if (!h) { printf("OpenProcess failed\n"); return 2; }
    DWORD sz = 0;
    ULONG_PTR sdk = find_module(pid, "SecurityGuardSDK64.dll", &sz);
    printf("PID=%lu  SDK=%p\n", pid, (void *)sdk);

    ULONG_PTR buf = sdk + 0xA2A281;
    printf("GUID 缓冲区 = %p\n", (void *)buf);

    /* 确认内容 */
    char verify[64] = {0};
    SIZE_T g = 0;
    if (ReadProcessMemory(h, (LPCVOID)buf, verify, 40, &g) && g >= 36) {
        verify[36] = 0;
        printf("  内容: \"%s\"\n", verify);
    } else {
        printf("  读取失败\n"); return 3;
    }

    /* 搜索指向该地址的 8 字节指针 */
    printf("\n== 搜索指向该缓冲区的指针 ==\n");
    const SIZE_T CHUNK = 1 << 20;
    unsigned char *region = (unsigned char *)malloc(CHUNK);
    MEMORY_BASIC_INFORMATION mbi;
    ULONG_PTR a = 0;
    int hits = 0;

    while (VirtualQueryEx(h, (LPCVOID)a, &mbi, sizeof(mbi))) {
        if (mbi.State == MEM_COMMIT &&
            (mbi.Protect == PAGE_READWRITE || mbi.Protect == PAGE_WRITECOPY ||
             mbi.Protect == PAGE_READWRITE)) {
            ULONG_PTR rs = (ULONG_PTR)mbi.BaseAddress, re = rs + mbi.RegionSize;
            for (ULONG_PTR q = rs; q < re; q += CHUNK) {
                SIZE_T want = (SIZE_T)((re - q) < CHUNK ? (re - q) : CHUNK);
                SIZE_T got = 0;
                if (!ReadProcessMemory(h, (LPCVOID)q, region, want, &got) || got < 8) continue;
                for (SIZE_T i = 0; i + 8 <= got; i += 8) {
                    ULONG_PTR v; memcpy(&v, region + i, 8);
                    if (v == buf) {
                        printf("  指针 @ 0x%llx\n", (unsigned long long)(q + i));
                        hits++;
                        if (hits >= 10) break;
                    }
                }
                if (hits >= 10) break;
            }
        }
        if (hits >= 10) break;
        a = (ULONG_PTR)mbi.BaseAddress + mbi.RegionSize;
        if (a < (ULONG_PTR)mbi.BaseAddress) break;
    }
    if (!hits) printf("  无指针（可能是栈上临时引用或按值传递）\n");

    /* 搜索 GUID 文本的其他副本（堆上的拷贝） */
    printf("\n== 搜索 GUID 文本副本 ==\n");
    const char *needle = "3be229e1-301d-4639-b88a-16997824d71b";
    size_t nlen = strlen(needle);
    a = 0;
    int copies = 0;
    while (VirtualQueryEx(h, (LPCVOID)a, &mbi, sizeof(mbi)) && copies < 8) {
        if (mbi.State == MEM_COMMIT &&
            (mbi.Protect == PAGE_READWRITE || mbi.Protect == PAGE_READONLY ||
             mbi.Protect == PAGE_WRITECOPY)) {
            ULONG_PTR rs = (ULONG_PTR)mbi.BaseAddress, re = rs + mbi.RegionSize;
            for (ULONG_PTR q = rs; q < re; q += CHUNK) {
                SIZE_T want = (SIZE_T)((re - q) < CHUNK ? (re - q) : CHUNK);
                SIZE_T got = 0;
                if (!ReadProcessMemory(h, (LPCVOID)q, region, want, &got)) continue;
                for (SIZE_T i = 0; i + nlen <= got; i++) {
                    if (memcmp(region + i, needle, nlen) == 0) {
                        printf("  @ 0x%llx  (SDK+0x%llx)\n",
                               (unsigned long long)(q + i),
                               (unsigned long long)((q + i) - sdk));
                        copies++;
                        if (copies >= 8) break;
                    }
                }
            }
        }
        a = (ULONG_PTR)mbi.BaseAddress + mbi.RegionSize;
        if (a < (ULONG_PTR)mbi.BaseAddress) break;
    }

    free(region);
    CloseHandle(h);
    return 0;
}