/**
 * 在钉钉进程内调用 getSecurityToken 并观察行为
 *
 * ABI（从 MainFrame 的调用点逆向，RVA 0xa8db）：
 *   getSecurityToken(rcx=factors 字符串, rdx=?, r8=void** out)
 *
 * 实测策略：
 *   1. 先试 1 参数形态（factors only）
 *   2. 再试 3 参数形态
 *   3. 每次调用后检查 SDK 内部状态变化（如 0xA2A281 缓冲区）
 *
 * 编译：cl /nologo /O2 /Fe:call-token.exe call-token.c advapi32.lib Psapi.lib
 */
#include <windows.h>
#include <stdio.h>
#include <tlhelp32.h>
#include <psapi.h>
#include <string.h>

static DWORD g_pid;
static HANDLE g_hProc;
static ULONG_PTR g_sdk, g_sdkEnd;

static void setup(void) {
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
            g_sdk = (ULONG_PTR)me.modBaseAddr;
            g_sdkEnd = g_sdk + me.modBaseSize;
            break;
        }
    } while (Module32Next(ms, &me));
    CloseHandle(ms);

    g_hProc = OpenProcess(
        PROCESS_CREATE_THREAD | PROCESS_QUERY_INFORMATION | PROCESS_VM_OPERATION |
        PROCESS_VM_WRITE | PROCESS_VM_READ, FALSE, g_pid);
}

/** 远程调用，最多 4 参数，返回 64 位 */
static BOOL remote_call64(ULONG_PTR fn, ULONG_PTR a1, ULONG_PTR a2,
                          ULONG_PTR a3, ULONG_PTR a4, ULONG_PTR *outRet) {
    unsigned char code[80];
    int n = 0;
    #define MOV_IMM(regNum, val) do { \
        code[n++] = 0x48; code[n++] = (unsigned char)(0xB8 + (regNum)); \
        ULONG_PTR v = (ULONG_PTR)(val); memcpy(code + n, &v, 8); n += 8; } while (0)

    if (a1) MOV_IMM(1, a1);
    if (a2) MOV_IMM(2, a2);
    if (a3) MOV_IMM(8, a3);
    if (a4) MOV_IMM(9, a4);
    MOV_IMM(0, fn);
    code[n++] = 0xFF; code[n++] = 0xD0;   /* call rax */
    code[n++] = 0xC3;                      /* ret */
    #undef MOV_IMM

    LPVOID pCode = VirtualAllocEx(g_hProc, NULL, n, MEM_COMMIT | MEM_RESERVE,
                                  PAGE_EXECUTE_READWRITE);
    if (!pCode) return FALSE;
    if (!WriteProcessMemory(g_hProc, pCode, code, n, NULL)) {
        VirtualFreeEx(g_hProc, pCode, 0, MEM_RELEASE);
        return FALSE;
    }

    HANDLE th = CreateRemoteThread(g_hProc, NULL, 0,
                                   (LPTHREAD_START_ROUTINE)pCode, NULL, 0, NULL);
    if (!th) { VirtualFreeEx(g_hProc, pCode, 0, MEM_RELEASE); return FALSE; }

    DWORD wr = WaitForSingleObject(th, 15000);
    DWORD rc32 = 0;
    GetExitCodeThread(th, &rc32);
    if (outRet) *outRet = (ULONG_PTR)(ULONG64)rc32;
    CloseHandle(th);
    VirtualFreeEx(g_hProc, pCode, 0, MEM_RELEASE);
    return wr == WAIT_OBJECT_0;
}

static void snapshot(const char *label) {
    /* 记录 x5-sign 缓存区状态 */
    ULONG_PTR buf = g_sdk + 0xA2A281;
    char s[64] = {0};
    ReadProcessMemory(g_hProc, (LPCVOID)buf, s, 40, NULL);
    printf("  [%s] SDK+0xA2A281: \"%.36s\"\n", label, s);
}

int main(void) {
    SetConsoleOutputCP(CP_UTF8);
    printf("=== 在钉钉进程内调用 getSecurityToken ===\n");

    setup();
    if (!g_hProc || !g_sdk) { printf("初始化失败\n"); return 1; }
    printf("PID=%lu SDK=%p\n\n", g_pid, (void *)g_sdk);

    ULONG_PTR getTok = g_sdk + 0x182380;
    snapshot("调用前");

    /* 写 factors 字符串到目标进程 */
    const char *factors = "28695415,appkey,api";
    SIZE_T flen = strlen(factors) + 1;
    LPVOID pFactors = VirtualAllocEx(g_hProc, NULL, flen, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    WriteProcessMemory(g_hProc, pFactors, factors, flen, NULL);

    /* 输出指针缓冲区 */
    LPVOID pOut = VirtualAllocEx(g_hProc, NULL, 64, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    { unsigned char z[64] = {0}; WriteProcessMemory(g_hProc, pOut, z, 64, NULL); }

    printf("\n[测试 A] getSecurityToken(factors) —— 1 参数\n");
    ULONG_PTR ret = 0;
    if (remote_call64(getTok, (ULONG_PTR)pFactors, 0, 0, 0, &ret)) {
        printf("  返回 0x%llx (%lld)\n", (unsigned long long)ret, (long long)(int)ret);
    } else {
        printf("  调用异常\n");
    }
    snapshot("A 之后");

    printf("\n[测试 B] getSecurityToken(factors, 0, &out) —— 3 参数\n");
    { unsigned char z[64] = {0}; WriteProcessMemory(g_hProc, pOut, z, 64, NULL); }
    if (remote_call64(getTok, (ULONG_PTR)pFactors, 0, (ULONG_PTR)pOut, 0, &ret)) {
        printf("  返回 0x%llx (%lld)\n", (unsigned long long)ret, (long long)(int)ret);
        ULONG_PTR outv = 0;
        ReadProcessMemory(g_hProc, pOut, &outv, 8, NULL);
        printf("  *out = 0x%llx\n", (unsigned long long)outv);
    } else {
        printf("  调用异常\n");
    }
    snapshot("B 之后");

    printf("\n[测试 C] getSecurityToken(0, 0, &out) —— 空 factors\n");
    { unsigned char z[64] = {0}; WriteProcessMemory(g_hProc, pOut, z, 64, NULL); }
    if (remote_call64(getTok, 0, 0, (ULONG_PTR)pOut, 0, &ret)) {
        printf("  返回 0x%llx (%lld)\n", (unsigned long long)ret, (long long)(int)ret);
    } else {
        printf("  调用异常\n");
    }
    snapshot("C 之后");

    VirtualFreeEx(g_hProc, pFactors, 0, MEM_RELEASE);
    VirtualFreeEx(g_hProc, pOut, 0, MEM_RELEASE);
    CloseHandle(g_hProc);
    printf("\n完成\n");
    return 0;
}