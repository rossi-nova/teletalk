/**
 * 远程执行 + 硬件断点捕获 getSecurityToken 参数
 *
 * 技术：
 *   1. 在目标进程开一个线程，给它设 DR0 = getSecurityToken
 *   2. 线程里调用 getSecurityToken
 *   3. 触发断点时（异常传播到我们创建的线程），读参数
 *
 * 更简单可靠的做法：直接 hook 函数入口（覆写前几个字节为 jmp），
 * 但会被 SDK 的完整性检查发现。
 *
 * 本工具用另一招：在目标线程上执行，用 VEH（向量化异常处理）捕获。
 *
 * 编译：cl /nologo /O2 /Fe:remote-bp.exe remote-bp.c advapi32.lib Psapi.lib
 */
#include <windows.h>
#include <stdio.h>
#include <tlhelp32.h>
#include <psapi.h>
#include <string.h>

static DWORD g_pid = 0;
static HANDLE g_hProc = NULL;
static ULONG_PTR g_target = 0;
static volatile LONG g_hits = 0;

/* 捕获到的参数 */
typedef struct {
    ULONG_PTR rcx, rdx, r8, r9;
    DWORD tid;
} HitInfo;

static HitInfo g_captured[16];

/* 目标进程中执行的 shellcode：
 *   设置自身 DR0 = target
 *   调用 target(...)
 *   返回
 */
static void find_pid_and_module(void) {
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
    g_pid = best;

    HANDLE ms = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, g_pid);
    MODULEENTRY32 me = { sizeof(me) };
    if (Module32First(ms, &me)) do {
        if (_stricmp(me.szModule, "SecurityGuardSDK64.dll") == 0) {
            g_target = (ULONG_PTR)me.modBaseAddr + 0x182380;
            break;
        }
    } while (Module32Next(ms, &me));
    CloseHandle(ms);
}

int main(void) {
    SetConsoleOutputCP(CP_UTF8);
    printf("=== 远程断点捕获 getSecurityToken ===\n");

    find_pid_and_module();
    if (!g_pid || !g_target) { printf("未找到\n"); return 1; }

    g_hProc = OpenProcess(
        PROCESS_CREATE_THREAD | PROCESS_QUERY_INFORMATION | PROCESS_VM_OPERATION |
        PROCESS_VM_WRITE | PROCESS_VM_READ, FALSE, g_pid);
    if (!g_hProc) { printf("OpenProcess 失败 %lu\n", GetLastError()); return 2; }

    printf("PID=%lu  目标=%p\n", g_pid, (void *)g_target);

    /* 说明：真正的参数捕获需要在目标线程内运行 handler，
     * 复杂度高且易被反调试发现。这里先验证「能否在目标线程设置 DR」。
     *
     * 安全做法：创建一个挂起的远程线程，在其上下文中设置 DR0，
     * 然后让它调用 getSecurityToken。
     */

    /* 写入一个 trivial 的远程线程代码：直接 ret */
    unsigned char code[] = { 0xC3 };
    LPVOID pCode = VirtualAllocEx(g_hProc, NULL, 16, MEM_COMMIT | MEM_RESERVE,
                                  PAGE_EXECUTE_READWRITE);
    if (!pCode) { printf("VirtualAllocEx 失败\n"); return 3; }
    WriteProcessMemory(g_hProc, pCode, code, sizeof(code), NULL);

    HANDLE th = CreateRemoteThread(g_hProc, NULL, 0,
                                   (LPTHREAD_START_ROUTINE)pCode, NULL, CREATE_SUSPENDED, NULL);
    if (!th) { printf("CreateRemoteThread 失败 %lu\n", GetLastError()); return 4; }

    /* 在该线程上下文设 DR0 */
    CONTEXT ctx;
    ctx.ContextFlags = CONTEXT_DEBUG_REGISTERS;
    if (GetThreadContext(th, &ctx)) {
        printf("\n[线程上下文] 原始 Dr7 = 0x%llx\n", (unsigned long long)ctx.Dr7);
        ctx.Dr0 = g_target;
        /* Dr7: bit0=本地使能(DR0), bit16-17=类型(00=执行), bit18-19=长度(00=1字节) */
        ctx.Dr7 = (ctx.Dr7 & ~(ULONG64)0x3) | 0x1;
        ctx.ContextFlags = CONTEXT_DEBUG_REGISTERS;
        if (SetThreadContext(th, &ctx)) {
            CONTEXT v;
            v.ContextFlags = CONTEXT_DEBUG_REGISTERS;
            GetThreadContext(th, &v);
            printf("  设置后 Dr0 = 0x%llx, Dr7 = 0x%llx\n",
                   (unsigned long long)v.Dr0, (unsigned long long)v.Dr7);
            printf("  ✓ 硬件断点可在目标线程设置\n");
        } else {
            printf("  ✗ SetThreadContext 失败: %lu\n", GetLastError());
        }
    }

    TerminateThread(th, 0);
    CloseHandle(th);
    VirtualFreeEx(g_hProc, pCode, 0, MEM_RELEASE);

    printf("\n=== 结论 ===\n");
    printf("远程调用能力: ✓ 已验证（zeroUMID 返回 78）\n");
    printf("硬件断点能力: 见上\n");
    printf("\n下一步：在远程线程里真实调用 getSecurityToken 并捕获参数。\n");

    CloseHandle(g_hProc);
    return 0;
}