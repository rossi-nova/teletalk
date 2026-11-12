/**
 * 用硬件断点捕获 getSecurityToken 的真实调用
 *
 * 原理：
 *   1. 附加到钉钉进程（调试器身份）
 *   2. 在 SDK 的 getSecurityToken 入口设执行断点
 *   3. 命中时读 rcx/rdx/r8（x64 前三个参数）
 *   4. 继续执行，记录所有命中
 *
 * 优点：不修改目标内存 → 反调试（Detours/CRC 校验）不易发现
 * 缺点：需要较高权限；附加会短暂冻结进程
 *
 * 编译：cl /nologo /O2 /Fe:hwbp.exe hwbp.c
 * 运行：需管理员
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

static ULONG_PTR find_module(DWORD pid, const char *name) {
    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, pid);
    if (snap == INVALID_HANDLE_VALUE) return 0;
    MODULEENTRY32 me = { sizeof(me) };
    ULONG_PTR base = 0;
    if (Module32First(snap, &me)) do {
        if (_stricmp(me.szModule, name) == 0) { base = (ULONG_PTR)me.modBaseAddr; break; }
    } while (Module32Next(snap, &me));
    CloseHandle(snap);
    return base;
}

static void print_wide_or_ansi(HANDLE h, ULONG_PTR addr, const char *label) {
    if (!addr || addr < 0x10000) { printf("    %s = 0x%llx (无效)\n", label, (unsigned long long)addr); return; }
    wchar_t w[128] = {0};
    SIZE_T g = 0;
    if (ReadProcessMemory(h, (LPCVOID)addr, w, sizeof(w) - 2, &g) && g > 2) {
        if (w[0] >= 0x20 && w[0] < 0x2000) {
            wprintf(L"    %s = L\"%.80s\"\n", label, w);
            return;
        }
    }
    char a[128] = {0};
    if (ReadProcessMemory(h, (LPCVOID)addr, a, sizeof(a) - 1, &g) && g > 2) {
        int pr = 0;
        for (int i = 0; i < 40 && a[i]; i++) if (a[i] >= 0x20 && a[i] < 0x7f) pr++;
        if (pr >= 4) { printf("    %s = \"%.80s\"\n", label, a); return; }
    }
    printf("    %s = 0x%llx (数据)\n", label, (unsigned long long)addr);
}

int main(int argc, char **argv) {
    SetConsoleOutputCP(CP_UTF8);
    printf("=== getSecurityToken 硬件断点捕获 ===\n\n");

    DWORD pid = find_pid();
    if (!pid) { printf("未找到 DingTalk.exe\n"); return 1; }
    printf("目标 PID = %lu\n", pid);

    ULONG_PTR sdk = find_module(pid, "SecurityGuardSDK64.dll");
    if (!sdk) { printf("SDK 未加载\n"); return 2; }
    ULONG_PTR target = sdk + 0x182380;
    printf("getSecurityToken @ %p\n\n", (void *)target);

    if (!DebugActiveProcess(pid)) {
        printf("DebugActiveProcess 失败: %lu\n", GetLastError());
        if (GetLastError() == 5) printf("  → 需要管理员权限\n");
        return 3;
    }
    DebugSetProcessKillOnExit(FALSE);
    printf("已附加。设置断点…\n");

    /* 在目标线程上设硬件执行断点（DR0） */
    int armed = 0;
    ULONG_PTR armedTid = 0;

    DEBUG_EVENT de;
    int hits = 0;
    DWORD startTime = GetTickCount();
    const DWORD RUN_MS = 120000;   /* 最多跑 2 分钟 */

    while (GetTickCount() - startTime < RUN_MS) {
        if (!WaitForDebugEvent(&de, 1000)) continue;
        DWORD cont = DBG_CONTINUE;

        if (de.dwDebugEventCode == CREATE_THREAD_DEBUG_EVENT && !armed) {
            HANDLE th = OpenThread(THREAD_ALL_ACCESS, FALSE, de.dwThreadId);
            if (th) {
                CONTEXT ctx;
                ctx.ContextFlags = CONTEXT_DEBUG_REGISTERS;
                if (GetThreadContext(th, &ctx)) {
                    ctx.Dr0 = target;
                    ctx.Dr7 = (ctx.Dr7 & ~(ULONG64)0x3) | 0x1;  /* 本地启用 DR0，执行断点 */
                    ctx.ContextFlags = CONTEXT_DEBUG_REGISTERS;
                    SetThreadContext(th, &ctx);
                    if (!armed) { armed = 1; armedTid = de.dwThreadId;
                        printf("已在线程 %lu 上设置 DR0 断点\n", de.dwThreadId); }
                }
                CloseHandle(th);
            }
        }
        else if (de.dwDebugEventCode == EXCEPTION_DEBUG_EVENT) {
            EXCEPTION_DEBUG_INFO *ei = &de.u.Exception;
            if (ei->ExceptionRecord.ExceptionCode == EXCEPTION_SINGLE_STEP ||
                ei->ExceptionRecord.ExceptionCode == EXCEPTION_BREAKPOINT) {
                ULONG_PTR ip = (ULONG_PTR)ei->ExceptionRecord.ExceptionAddress;
                if (ip == target) {
                    hits++;
                    HANDLE th = OpenThread(THREAD_ALL_ACCESS, FALSE, de.dwThreadId);
                    HANDLE ph = OpenProcess(PROCESS_VM_READ, FALSE, pid);
                    if (th && ph) {
                        CONTEXT ctx;
                        ctx.ContextFlags = CONTEXT_CONTROL | CONTEXT_INTEGER;
                        if (GetThreadContext(th, &ctx)) {
                            printf("\n[命中 #%d] 线程 %lu\n", hits, de.dwThreadId);
                            printf("  rcx = 0x%llx  (参数1)\n", (unsigned long long)ctx.Rcx);
                            printf("  rdx = 0x%llx  (参数2)\n", (unsigned long long)ctx.Rdx);
                            printf("  r8  = 0x%llx  (参数3)\n", (unsigned long long)ctx.R8);
                            printf("  r9  = 0x%llx  (参数4)\n", (unsigned long long)ctx.R9);
                            print_wide_or_ansi(ph, ctx.Rcx, "rcx→");
                            print_wide_or_ansi(ph, ctx.Rdx, "rdx→");
                            print_wide_or_ansi(ph, ctx.R8,  "r8→");
                        }
                    }
                    if (th) CloseHandle(th);
                    if (ph) CloseHandle(ph);
                }
            }
        }

        ContinueDebugEvent(de.dwProcessId, de.dwThreadId, cont);
        if (hits >= 10) break;
    }

    DebugActiveProcessStop(pid);
    printf("\n共命中 %d 次\n", hits);
    return hits ? 0 : 4;
}
