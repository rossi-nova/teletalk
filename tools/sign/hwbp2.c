/**
 * 短时附加捕获 getSecurityToken（避免长时间冻结钉钉）
 *
 * 改进：
 *   1. 只附加 20 秒，捕获期间不阻塞（每次事件立即继续）
 *   2. 同时给所有现有线程设 DR0（不只是新线程）
 *   3. 命中后立刻记录并继续，不暂停进程
 *
 * 编译：cl /nologo /O2 /Fe:hwbp2.exe hwbp2.c
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

/** 给进程内所有线程设 DR0 */
static int arm_all_threads(DWORD pid, ULONG_PTR target) {
    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
    if (snap == INVALID_HANDLE_VALUE) return 0;
    THREADENTRY32 te = { sizeof(te) };
    int n = 0;
    if (Thread32First(snap, &te)) do {
        if (te.th32OwnerProcessID != pid) continue;
        HANDLE th = OpenThread(THREAD_ALL_ACCESS, FALSE, te.th32ThreadID);
        if (!th) continue;
        CONTEXT ctx;
        ctx.ContextFlags = CONTEXT_DEBUG_REGISTERS;
        if (GetThreadContext(th, &ctx)) {
            ctx.Dr0 = target;
            ctx.Dr7 = (ctx.Dr7 & ~(ULONG64)0x3) | 0x1;
            ctx.ContextFlags = CONTEXT_DEBUG_REGISTERS;
            SetThreadContext(th, &ctx);
            n++;
        }
        CloseHandle(th);
    } while (Thread32Next(snap, &te));
    CloseHandle(snap);
    return n;
}

int main(int argc, char **argv) {
    SetConsoleOutputCP(CP_UTF8);
    printf("=== 短时附加捕获 ===\n");

    DWORD pid = find_pid();
    if (!pid) { printf("未找到 DingTalk\n"); return 1; }
    ULONG_PTR sdk = find_module(pid, "SecurityGuardSDK64.dll");
    if (!sdk) { printf("SDK 未加载\n"); return 2; }

    ULONG_PTR target = sdk + 0x182380;
    printf("PID=%lu  getSecurityToken=%p\n", pid, (void *)target);
    printf("附加中（最多 25 秒）…\n");

    if (!DebugActiveProcess(pid)) {
        printf("DebugActiveProcess 失败: %lu\n", GetLastError());
        return 3;
    }
    DebugSetProcessKillOnExit(FALSE);

    /* 附加后立刻给所有线程设断点 */
    int armed = arm_all_threads(pid, target);
    printf("已在 %d 个线程设置断点\n", armed);

    DEBUG_EVENT de;
    int hits = 0;
    DWORD t0 = GetTickCount();
    const DWORD RUN_MS = 25000;

    while (GetTickCount() - t0 < RUN_MS) {
        DWORD remain = RUN_MS - (GetTickCount() - t0);
        if (!WaitForDebugEvent(&de, remain > 200 ? 200 : remain)) continue;

        if (de.dwDebugEventCode == EXCEPTION_DEBUG_EVENT) {
            EXCEPTION_DEBUG_INFO *ei = &de.u.Exception;
            if (ei->ExceptionRecord.ExceptionCode == EXCEPTION_SINGLE_STEP) {
                ULONG_PTR ip = (ULONG_PTR)ei->ExceptionRecord.ExceptionAddress;
                if (ip == target) {
                    hits++;
                    HANDLE th = OpenThread(THREAD_ALL_ACCESS, FALSE, de.dwThreadId);
                    HANDLE ph = OpenProcess(PROCESS_VM_READ, FALSE, pid);
                    if (th && ph) {
                        CONTEXT ctx;
                        ctx.ContextFlags = CONTEXT_CONTROL | CONTEXT_INTEGER;
                        if (GetThreadContext(th, &ctx)) {
                            printf("\n[#%d tid=%lu]\n", hits, de.dwThreadId);
                            printf("  rcx=%llx rdx=%llx r8=%llx r9=%llx\n",
                                   (unsigned long long)ctx.Rcx, (unsigned long long)ctx.Rdx,
                                   (unsigned long long)ctx.R8, (unsigned long long)ctx.R9);
                            /* 读 rcx（可能是 handle 或字符串） */
                            char s[96] = {0};
                            SIZE_T g = 0;
                            if (ctx.Rcx > 0x10000 &&
                                ReadProcessMemory(ph, (LPCVOID)ctx.Rcx, s, sizeof(s) - 1, &g) && g > 4) {
                                int pr = 0;
                                for (SIZE_T i = 0; i < g && i < 60; i++)
                                    if (s[i] >= 0x20 && s[i] < 0x7f) pr++; else break;
                                if (pr >= 4) printf("  rcx→ \"%.80s\"\n", s);
                            }
                            memset(s, 0, sizeof(s));
                            if (ctx.Rdx > 0x10000 &&
                                ReadProcessMemory(ph, (LPCVOID)ctx.Rdx, s, sizeof(s) - 1, &g) && g > 4) {
                                int pr = 0;
                                for (SIZE_T i = 0; i < g && i < 60; i++)
                                    if (s[i] >= 0x20 && s[i] < 0x7f) pr++; else break;
                                if (pr >= 4) printf("  rdx→ \"%.80s\"\n", s);
                            }
                            /* 参数3 通常是输出指针，打印其后的值 */
                            ULONG_PTR outv = 0;
                            if (ctx.R8 > 0x10000 &&
                                ReadProcessMemory(ph, (LPCVOID)ctx.R8, &outv, 8, NULL))
                                printf("  *r8 = 0x%llx\n", (unsigned long long)outv);
                        }
                    }
                    if (th) CloseHandle(th);
                    if (ph) CloseHandle(ph);
                }
            }
        }

        ContinueDebugEvent(de.dwProcessId, de.dwThreadId, DBG_CONTINUE);
        if (hits >= 5) break;
    }

    DebugActiveProcessStop(pid);
    printf("\n共命中 %d 次\n", hits);
    return hits ? 0 : 4;
}
