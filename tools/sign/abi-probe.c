/**
 * teletalk 签名探针 v3 — ABI 暴力枚举
 *
 * initUMID 的真实行为未知，逐个试参数组合，记录返回值与输出指针变化。
 */
#include <windows.h>
#include <stdio.h>
#include <string.h>

typedef long long (*fn_iii)(long long, long long, long long);
typedef long long (*fn_ii)(long long, long long);
typedef long long (*fn_i)(long long);

static HMODULE g_sdk;

static void hexdump(const char *label, const void *p, int n) {
    const unsigned char *b = (const unsigned char *)p;
    printf("%s", label);
    for (int i = 0; i < n; i++) printf("%02x ", b[i]);
    printf("\n");
}

static void try_init(const char *desc, fn_iii f, long long a, long long b, long long c) {
    printf("\n--- %s ---\n", desc);
    printf("  args: 0x%llx, 0x%llx, 0x%llx\n", a, b, c);
    long long rc = f(a, b, c);
    printf("  ret = 0x%llx (%lld)\n", (unsigned long long)rc, rc);
}

int main(void) {
    SetConsoleOutputCP(CP_UTF8);
    printf("=== teletalk ABI 枚举 ===\n");

    g_sdk = LoadLibraryA("SecurityGuardSDK64.dll");
    if (!g_sdk) { printf("加载失败 %lu\n", GetLastError()); return 1; }

    fn_iii init3 = (fn_iii)GetProcAddress(g_sdk, "initUMID");
    printf("initUMID @ %p\n", (void *)init3);

    /* 尝试 1: 3 参数，第三个是局部变量地址 */
    union { void *p; long long u; unsigned char raw[64]; } out;
    memset(&out, 0, sizeof(out));
    try_init("init(prefix, 0x33, &out)", init3, (long long)L"Windows.Security.Credentials.UI.", 0x33, (long long)&out);
    hexdump("  out[0..32]: ", out.raw, 32);

    /* 尝试 2: 第三个参数是 0 */
    memset(&out, 0, sizeof(out));
    try_init("init(prefix, 0x33, NULL)", init3, (long long)L"Windows.Security.Credentials.UI.", 0x33, 0);
    hexdump("  out[0..32]: ", out.raw, 32);

    /* 尝试 3: 只有两个参数（r8 随便） */
    memset(&out, 0, sizeof(out));
    try_init("init(prefix, 0x33, out_stack)", init3, (long long)L"Windows.Security.Credentials.UI.", 0x33, (long long)out.raw);
    hexdump("  out[0..32]: ", out.raw, 32);

    /* 尝试 4: 用 0 作为 flags */
    memset(&out, 0, sizeof(out));
    try_init("init(prefix, 0, &out)", init3, (long long)L"Windows.Security.Credentials.UI.", 0, (long long)&out);
    hexdump("  out[0..32]: ", out.raw, 32);

    FreeLibrary(g_sdk);
    return 0;
}
