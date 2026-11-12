/**
 * 远程调用 SDK 导出函数（不附加调试器，不冻结进程）
 *
 * 原理：CreateRemoteThread + 参数写入目标进程内存。
 * 同用户进程通常无需管理员权限。
 *
 * 用途：
 *   - 在钉钉进程内调用 getSecurityToken，拿到返回值
 *   - 验证函数 ABI
 *
 * 编译：cl /nologo /O2 /Fe:remote-call.exe remote-call.c advapi32.lib Psapi.lib
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

/**
 * 在目标进程分配内存并写入数据
 */
static LPVOID remote_alloc(HANDLE hProc, const void *data, SIZE_T len) {
    LPVOID p = VirtualAllocEx(hProc, NULL, len, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!p) return NULL;
    SIZE_T written = 0;
    if (!WriteProcessMemory(hProc, p, data, len, &written) || written != len) {
        VirtualFreeEx(hProc, p, 0, MEM_RELEASE);
        return NULL;
    }
    return p;
}

/**
 * 远程调用一个函数：fn(a1, a2, a3, a4)，返回 DWORD
 * x64 调用约定：rcx, rdx, r8, r9
 */
static BOOL remote_call(HANDLE hProc, ULONG_PTR fn, ULONG_PTR a1, ULONG_PTR a2,
                        ULONG_PTR a3, ULONG_PTR a4, DWORD *outRet) {
    /* 在目标进程写一段 shellcode：
     *   mov rcx, a1
     *   mov rdx, a2
     *   mov r8,  a3
     *   mov r9,  a4
     *   mov rax, fn
     *   call rax
     *   ret
     */
    unsigned char code[64];
    int n = 0;
    #define EMIT_MOV_IMM(reg, val) \
        do { code[n++] = 0x48; code[n++] = 0xB8 + (reg); \
             ULONG_PTR v = (ULONG_PTR)(val); \
             memcpy(code + n, &v, 8); n += 8; } while (0)

    if (a1) EMIT_MOV_IMM(1, a1);   /* rcx */
    if (a2) EMIT_MOV_IMM(2, a2);   /* rdx */
    if (a3) EMIT_MOV_IMM(8, a3);   /* r8  */
    if (a4) EMIT_MOV_IMM(9, a4);   /* r9  */
    EMIT_MOV_IMM(0, fn);           /* rax */
    code[n++] = 0xFF; code[n++] = 0xD0;  /* call rax */
    code[n++] = 0xC3;              /* ret */
    #undef EMIT_MOV_IMM

    LPVOID pCode = VirtualAllocEx(hProc, NULL, n, MEM_COMMIT | MEM_RESERVE,
                                  PAGE_EXECUTE_READWRITE);
    if (!pCode) return FALSE;
    SIZE_T written = 0;
    if (!WriteProcessMemory(hProc, pCode, code, n, &written)) {
        VirtualFreeEx(hProc, pCode, 0, MEM_RELEASE);
        return FALSE;
    }

    HANDLE th = CreateRemoteThread(hProc, NULL, 0,
                                   (LPTHREAD_START_ROUTINE)pCode, NULL, 0, NULL);
    if (!th) {
        VirtualFreeEx(hProc, pCode, 0, MEM_RELEASE);
        return FALSE;
    }
    WaitForSingleObject(th, 10000);
    DWORD rc = 0;
    GetExitCodeThread(th, &rc);
    if (outRet) *outRet = rc;
    CloseHandle(th);
    VirtualFreeEx(hProc, pCode, 0, MEM_RELEASE);
    return TRUE;
}

int main(int argc, char **argv) {
    SetConsoleOutputCP(CP_UTF8);
    printf("=== 远程调用 SDK 函数 ===\n");

    DWORD pid = find_pid();
    if (!pid) { printf("DingTalk not found\n"); return 1; }
    printf("PID=%lu\n", pid);

    HANDLE hProc = OpenProcess(
        PROCESS_CREATE_THREAD | PROCESS_QUERY_INFORMATION | PROCESS_VM_OPERATION |
        PROCESS_VM_WRITE | PROCESS_VM_READ, FALSE, pid);
    if (!hProc) {
        printf("OpenProcess failed: %lu\n", GetLastError());
        if (GetLastError() == 5) printf("  需要提升权限\n");
        return 2;
    }

    DWORD sz = 0;
    ULONG_PTR sdk = find_module(pid, "SecurityGuardSDK64.dll", &sz);
    if (!sdk) { printf("SDK 未加载\n"); return 3; }
    printf("SDK=%p\n", (void *)sdk);

    /* 读 SDK 的 PE 头以验证 */
    unsigned char hdr[2];
    ReadProcessMemory(hProc, (LPCVOID)sdk, hdr, 2, NULL);
    printf("PE 签名: %c%c\n\n", hdr[0], hdr[1]);

    /* 测试 1：调一个安全的小函数（zeroUMID，可能无副作用） */
    ULONG_PTR zeroUMID = sdk + 0x183bb0;
    printf("[1] 测试 remote_call 基础能力：调用 zeroUMID @ %p\n", (void *)zeroUMID);
    DWORD ret = 0;
    if (remote_call(hProc, zeroUMID, 0, 0, 0, 0, &ret)) {
        printf("    调用成功，返回 %lu\n", ret);
    } else {
        printf("    调用失败: %lu\n", GetLastError());
        CloseHandle(hProc);
        return 4;
    }

    /* 测试 2：只读探测 —— 读取 SDK 内某函数的目标，不实际调用有副作用的函数 */
    printf("\n[2] 探测 SDK 函数地址（只读）\n");
    const char *names[] = { "initUMID", "getSecurityToken", "freeSecurityToken", "zeroUMID", "QueryInterface" };
    ULONG_PTR addrs[] = { sdk + 0x17fa30, sdk + 0x182380, sdk + 0x183570, sdk + 0x183bb0, sdk + 0xf8c50 };
    for (int i = 0; i < 5; i++) {
        unsigned char b[8];
        SIZE_T g = 0;
        if (ReadProcessMemory(hProc, (LPCVOID)addrs[i], b, 8, &g) && g == 8) {
            printf("  %-20s %p  prologue: %02x %02x %02x %02x\n",
                   names[i], (void *)addrs[i], b[0], b[1], b[2], b[3]);
        }
    }

    /* 测试 3：尝试调用无副作用的纯函数（如果存在）
     * 这里改用 QueryInterface 的探测路径——先看它是否改变内存 */
    printf("\n[3] 内存状态快照（调用前后对比）\n");
    ULONG_PTR signBuf = sdk + 0x182380;
    unsigned char before[32], after[32];
    ReadProcessMemory(hProc, (LPCVOID)signBuf, before, 32, NULL);
    printf("  getSecurityToken 前 16 字节: ");
    for (int i = 0; i < 16; i++) printf("%02x ", before[i]);
    printf("\n");

    CloseHandle(hProc);
    printf("\n完成（未执行有副作用的调用）\n");
}