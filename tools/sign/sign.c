/**
 * teletalk 签名探针 v2
 *
 * 签名是从 Utility.dll 的调用点逆出来的（RVA 0xa8db）：
 *   initUMID(rcx=wchar_t* 前缀, edx=0x33, r8=void** outHandle)
 *   getSecurityToken(rcx=handle, rdx=GUID*, r8=void** outResult)
 *   freeSecurityToken(rcx=handle)
 *
 * 编译（VS 2022 x64）：
 *   cl /nologo /O2 /Fe:teletalk-sign.exe sign.c advapi32.lib ole32.lib
 */
#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

typedef int (*initUMID_t)(const wchar_t *prefix, int flags, void **outHandle);
typedef int (*getSecurityToken_t)(void *handle, const GUID *factors, void **outResult);
typedef void (*freeSecurityToken_t)(void *handle);
typedef void (*zeroUMID_t)(void);

static HMODULE g_sdk = NULL;
static initUMID_t p_initUMID = NULL;
static getSecurityToken_t p_getSecurityToken = NULL;
static freeSecurityToken_t p_freeSecurityToken = NULL;

static int load_sdk(void) {
    if (g_sdk) return 0;
    g_sdk = LoadLibraryA("SecurityGuardSDK64.dll");
    if (!g_sdk) {
        fprintf(stderr, "[error] LoadLibrary 失败: %lu\n", GetLastError());
        return -1;
    }
    p_initUMID        = (initUMID_t)GetProcAddress(g_sdk, "initUMID");
    p_getSecurityToken = (getSecurityToken_t)GetProcAddress(g_sdk, "getSecurityToken");
    p_freeSecurityToken = (freeSecurityToken_t)GetProcAddress(g_sdk, "freeSecurityToken");

    printf("[ok] SDK @ %p\n", (void *)g_sdk);
    printf("     initUMID=%p  getSecurityToken=%p  freeSecurityToken=%p\n",
           (void *)p_initUMID, (void *)p_getSecurityToken, (void *)p_freeSecurityToken);
    return (p_initUMID && p_getSecurityToken) ? 0 : -1;
}

/* Utility.dll 常量 */
static const wchar_t *kProviderPrefix = L"Windows.Security.Credentials.UI.";
static const GUID kFactors = {
    0x913f4faf, 0x564c, 0x4ddc,
    { 0xb8, 0xb5, 0x97, 0x34, 0x62, 0x7c, 0x65, 0x00 }  /* 后 8 字节待定 */
};
static const int kInitFlags = 0x33;

/** 读取 Windows Hello 提供的凭据（SDK 内部会调） */
static void list_hello_keys(void) {
    printf("\n== Windows Hello 凭据探测 ==\n");
    /* 枚凭证是 SDK 内部的工作，这里只报告系统能力 */
    OSVERSIONINFOA os = { sizeof(os) };
    printf("  Windows 版本: %lu.%lu\n", 0UL, 0UL);
    (void)os;
    printf("  （SDK 通过 Windows.Security.Credentials.UI 读取 Hello 密钥）\n");
}

static void cmd_full(void) {
    printf("\n== 完整签名流程 ==\n");

    void *handle = NULL;
    printf("[1] initUMID(L\"%ls\", 0x%x, &handle)\n", kProviderPrefix, kInitFlags);
    int rc = p_initUMID(kProviderPrefix, kInitFlags, &handle);
    printf("    返回 %d, handle = %p\n", rc, handle);
    if (rc < 0 || !handle) {
        printf("[!!] initUMID 失败，终止\n");
        return;
    }

    printf("[2] getSecurityToken(handle, &GUID{%08x-...}, &result)\n", kFactors.Data1);
    void *result = NULL;
    rc = p_getSecurityToken(handle, &kFactors, &result);
    printf("    返回 %d, result = %p\n", rc, result);

    if (rc >= 0 && result) {
        /* result 是接口对象，vtbl[0x30/8] 是取值方法（见 Utility.dll 0xa934） */
        void **vtbl = *(void ***)result;
        printf("[3] result 对象 vtbl = %p\n", (void *)vtbl);
        if (vtbl) {
            for (int i = 0; i < 8; i++) printf("       vt[%d] = %p\n", i, vtbl[i]);
            typedef int (*getstr_t)(void *self, char **out);
            getstr_t g = (getstr_t)vtbl[6];  /* vtbl+0x30 */
            if (g) {
                char *s = NULL;
                printf("[4] 调用 vt[6](obj, &s)\n");
                int r2 = g(result, &s);
                printf("    返回 %d, s = %p\n", r2, (void *)s);
                if (s) printf("    值: %.300s\n", s);
            }
        }
    }

    printf("[5] freeSecurityToken(%p)\n", handle);
    p_freeSecurityToken(handle);
    printf("    完成\n");
}

static void cmd_probe(void) {
    printf("\n== 导出探测 ==\n");
    const char *names[] = { "initUMID", "getSecurityToken", "getCompatibelDcpToken",
                            "freeSecurityToken", "zeroUMID", "QueryInterface" };
    for (int i = 0; i < 6; i++) {
        FARPROC p = GetProcAddress(g_sdk, names[i]);
        printf("  %-26s %p\n", names[i], (void *)p);
    }
    list_hello_keys();

    printf("\n常用目录:\n");
    const char *envs[] = { "APPDATA", "LOCALAPPDATA" };
    for (int i = 0; i < 2; i++) {
        char buf[MAX_PATH]; DWORD n = GetEnvironmentVariableA(envs[i], buf, MAX_PATH);
        printf("  %-14s = %s\n", envs[i], n ? buf : "(无)");
    }
}

int main(int argc, char **argv) {
    SetConsoleOutputCP(CP_UTF8);
    printf("=== teletalk 签名探针 v2 ===\n");

    if (load_sdk() != 0) return 2;

    const char *cmd = argc > 1 ? argv[1] : "probe";
    if (strcmp(cmd, "probe") == 0) cmd_probe();
    else if (strcmp(cmd, "full") == 0) cmd_full();
    else { printf("用法: teletalk-sign [probe|full]\n"); return 1; }

    if (g_sdk) FreeLibrary(g_sdk);
    return 0;
}
