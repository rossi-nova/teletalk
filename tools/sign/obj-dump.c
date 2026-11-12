/**
 * 深度读取 SDK 对象实例
 *
 * 已定位 ITrafficFilter 实例 @ 0x236225354a0（PID 5668 运行时地址，跨进程启动会变）
 * 本工具重新定位并打印对象的完整布局，追踪其中的指针链。
 *
 * 编译：cl /nologo /O2 /Fe:obj-dump.exe obj-dump.c advapi32.lib Psapi.lib
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

static ULONG_PTR find_module(DWORD pid, const char *name, DWORD *outSize) {
    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, pid);
    if (snap == INVALID_HANDLE_VALUE) return 0;
    MODULEENTRY32 me = { sizeof(me) };
    ULONG_PTR base = 0;
    if (Module32First(snap, &me)) do {
        if (_stricmp(me.szModule, name) == 0) { base = (ULONG_PTR)me.modBaseAddr; *outSize = me.modBaseSize; break; }
    } while (Module32Next(snap, &me));
    CloseHandle(snap);
    return base;
}

/** 判断指针是否指向可读内存 */
static int can_read(HANDLE h, ULONG_PTR addr, SIZE_T n) {
    MEMORY_BASIC_INFORMATION mbi;
    if (!VirtualQueryEx(h, (LPCVOID)addr, &mbi, sizeof(mbi))) return 0;
    if (mbi.State != MEM_COMMIT) return 0;
    if (mbi.Protect & (PAGE_NOACCESS | PAGE_GUARD)) return 0;
    ULONG_PTR end = (ULONG_PTR)mbi.BaseAddress + mbi.RegionSize;
    return (addr + n) <= end;
}

static ULONG_PTR g_sdkBase, g_sdkEnd;

static void describe_ptr(ULONG_PTR v) {
    if (v == 0) { printf("NULL"); return; }
    if (v >= g_sdkBase && v < g_sdkEnd) {
        printf("SDK+0x%llx", (unsigned long long)(v - g_sdkBase));
        return;
    }
    printf("0x%llx", (unsigned long long)v);
}

/** 找对象实例 */
static ULONG_PTR find_instance(HANDLE h, ULONG_PTR vtbl) {
    MEMORY_BASIC_INFORMATION mbi;
    ULONG_PTR addr = 0;
    const SIZE_T CHUNK = 1 << 20;
    unsigned char *buf = (unsigned char *)malloc(CHUNK);
    if (!buf) return 0;

    while (VirtualQueryEx(h, (LPCVOID)addr, &mbi, sizeof(mbi))) {
        if (mbi.State == MEM_COMMIT &&
            (mbi.Protect == PAGE_READWRITE || mbi.Protect == PAGE_READONLY ||
             mbi.Protect == PAGE_WRITECOPY)) {
            for (ULONG_PTR p = (ULONG_PTR)mbi.BaseAddress;
                 p < (ULONG_PTR)mbi.BaseAddress + mbi.RegionSize; p += CHUNK) {
                ULONG_PTR end = (ULONG_PTR)mbi.BaseAddress + mbi.RegionSize;
                SIZE_T want = (SIZE_T)((end - p) < CHUNK ? (end - p) : CHUNK);
                SIZE_T got = 0;
                if (!ReadProcessMemory(h, (LPCVOID)p, buf, want, &got) || got < 8) continue;
                for (SIZE_T i = 0; i + 8 <= got; i += 8) {
                    ULONG_PTR v; memcpy(&v, buf + i, 8);
                    if (v == vtbl) { free(buf); return p + i; }
                }
            }
        }
        addr = (ULONG_PTR)mbi.BaseAddress + mbi.RegionSize;
        if (addr < (ULONG_PTR)mbi.BaseAddress) break;
    }
    free(buf);
    return 0;
}

static void dump_object(HANDLE h, ULONG_PTR obj) {
    unsigned char buf[512];
    SIZE_T got = 0;
    printf("\n=== 对象 @ 0x%llx ===\n", (unsigned long long)obj);
    if (!ReadProcessMemory(h, (LPCVOID)obj, buf, sizeof(buf), &got) || got < 64) {
        printf("读取失败\n"); return;
    }

    printf("\n[字段视图] 偏移  值\n");
    for (int i = 0; i < 32; i++) {
        ULONG_PTR v; memcpy(&v, buf + i * 8, 8);
        printf("  +0x%02x  ", i * 8);
        describe_ptr(v);
        /* 若是字符串指针，试着读内容 */
        if (v && !(v >= g_sdkBase && v < g_sdkEnd) && can_read(h, v, 32)) {
            char s[128] = {0};
            SIZE_T sg = 0;
            if (ReadProcessMemory(h, (LPCVOID)v, s, sizeof(s) - 1, &sg) && sg > 4) {
                int printable = 0;
                for (SIZE_T k = 0; k < sg && k < 60; k++) {
                    if (s[k] >= 0x20 && s[k] < 0x7f) printable++;
                    else break;
                }
                if (printable >= 6) printf("   → \"%.60s\"", s);
            }
        }
        printf("\n");
    }

    /* 展开前几个非 NULL 指针 */
    printf("\n[指针展开]\n");
    for (int i = 1; i < 12; i++) {
        ULONG_PTR v; memcpy(&v, buf + i * 8, 8);
        if (!v || (v >= g_sdkBase && v < g_sdkEnd)) continue;
        if (!can_read(h, v, 64)) continue;
        unsigned char sub[64];
        SIZE_T sg = 0;
        if (!ReadProcessMemory(h, (LPCVOID)v, sub, sizeof(sub), &sg)) continue;
        printf("\n  +0x%02x → 0x%llx:\n", i * 8, (unsigned long long)v);
        for (int k = 0; k < 8; k++) {
            ULONG_PTR sv; memcpy(&sv, sub + k * 8, 8);
            printf("     [%d] ", k);
            describe_ptr(sv);
            /* 再深一层读字符串 */
            if (sv > 0x10000 && !(sv >= g_sdkBase && sv < g_sdkEnd) && can_read(h, sv, 24)) {
                char ss[96] = {0};
                SIZE_T s2 = 0;
                if (ReadProcessMemory(h, (LPCVOID)sv, ss, sizeof(ss) - 1, &s2) && s2 > 4) {
                    int pr = 0;
                    for (SIZE_T q = 0; q < s2 && q < 50; q++) {
                        if (ss[q] >= 0x20 && ss[q] < 0x7f) pr++; else break;
                    }
                    if (pr >= 5) printf("  → \"%.50s\"", ss);
                }
            }
            printf("\n");
        }
    }
}

int main(void) {
    SetConsoleOutputCP(CP_UTF8);
    printf("=== SDK 对象深度 dump ===\n");

    DWORD pid = find_pid();
    if (!pid) { printf("未找到 DingTalk.exe\n"); return 1; }
    HANDLE h = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, pid);
    if (!h) { printf("OpenProcess 失败 %lu\n", GetLastError()); return 2; }

    DWORD sdkSize = 0;
    g_sdkBase = find_module(pid, "SecurityGuardSDK64.dll", &sdkSize);
    if (!g_sdkBase) { printf("SDK 未加载\n"); return 3; }
    g_sdkEnd = g_sdkBase + sdkSize;

    printf("PID=%lu  SDK=%p  size=0x%x\n", pid, (void *)g_sdkBase, sdkSize);

    ULONG_PTR vt = g_sdkBase + 0x8e1438;
    printf("ITrafficFilter 虚表 = %p\n", (void *)vt);

    ULONG_PTR obj = find_instance(h, vt);
    if (!obj) { printf("未找到实例\n"); return 4; }
    printf("实例 @ 0x%llx\n", (unsigned long long)obj);

    dump_object(h, obj);

    CloseHandle(h);
    return 0;
}
