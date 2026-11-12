/**
 * 附加到运行中的钉钉进程，读取 SDK 的运行时状态
 *
 * 目标：不逆混淆代码，直接读已初始化的 SDK 内存
 *   - SDK 模块基址
 *   - SDK 中全局变量（句柄、单例）
 *   - 已生成的 token 缓存
 *
 * 编译：cl /nologo /O2 /Fe:mem-probe.exe mem-probe.c advapi32.lib
 */
#include <windows.h>
#include <stdio.h>
#include <tlhelp32.h>
#include <psapi.h>

static DWORD find_dingtalk_pid(void) {
    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snap == INVALID_HANDLE_VALUE) return 0;
    PROCESSENTRY32 pe = { sizeof(pe) };
    DWORD best = 0; SIZE_T bestWs = 0;
    if (Process32First(snap, &pe)) {
        do {
            if (_stricmp(pe.szExeFile, "DingTalk.exe") == 0) {
                HANDLE h = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pe.th32ProcessID);
                if (h) {
                    PROCESS_MEMORY_COUNTERS pmc;
                    if (GetProcessMemoryInfo(h, &pmc, sizeof(pmc)) && pmc.WorkingSetSize > bestWs) {
                        bestWs = pmc.WorkingSetSize;
                        best = pe.th32ProcessID;
                    }
                    CloseHandle(h);
                }
            }
        } while (Process32Next(snap, &pe));
    }
    CloseHandle(snap);
    return best;
}

int main(void) {
    SetConsoleOutputCP(CP_UTF8);
    printf("=== 钉钉进程内存探针 ===\n");

    DWORD pid = find_dingtalk_pid();
    if (!pid) { printf("未找到 DingTalk.exe\n"); return 1; }
    printf("目标 PID = %lu\n", pid);

    HANDLE h = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, pid);
    if (!h) {
        DWORD e = GetLastError();
        printf("OpenProcess 失败: %lu\n", e);
        if (e == 5) printf("  → 需要管理员权限\n");
        return 2;
    }
    printf("进程句柄已获取\n\n");

    /* 枚举模块 */
    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, pid);
    if (snap == INVALID_HANDLE_VALUE) { printf("模块快照失败 %lu\n", GetLastError()); CloseHandle(h); return 3; }

    MODULEENTRY32 me = { sizeof(me) };
    ULONG_PTR sdkBase = 0;
    ULONG_PTR sdkEnd = 0;

    printf("== 安全相关模块 ==\n");
    if (Module32First(snap, &me)) {
        do {
            if (strstr(me.szModule, "SecurityGuard") || strstr(me.szModule, "UTDID") ||
                strstr(me.szModule, "security")) {
                printf("  %-30s base=%p  size=0x%x\n", me.szModule,
                       (void *)me.modBaseAddr, me.modBaseSize);
                if (strstr(me.szModule, "SecurityGuard")) {
                    sdkBase = (ULONG_PTR)me.modBaseAddr;
                    sdkEnd = sdkBase + me.modBaseSize;
                }
            }
        } while (Module32Next(snap, &me));
    }
    CloseHandle(snap);

    if (!sdkBase) { printf("\nSDK 未加载\n"); CloseHandle(h); return 0; }
    printf("\nSDK 基址 = %p，大小 = 0x%llx\n", (void *)sdkBase, (unsigned long long)(sdkEnd - sdkBase));

    /* 读 SDK 首部验证 */
    unsigned char hdr[64];
    SIZE_T got = 0;
    if (ReadProcessMemory(h, (LPCVOID)sdkBase, hdr, sizeof(hdr), &got) && got == sizeof(hdr)) {
        printf("PE 头前 16 字节: ");
        for (int i = 0; i < 16; i++) printf("%02x ", hdr[i]);
        printf("\n");
    } else {
        printf("读 SDK 头失败: %lu\n", GetLastError());
    }

    CloseHandle(h);
    return 0;
}
