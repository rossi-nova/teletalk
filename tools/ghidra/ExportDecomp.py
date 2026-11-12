# -*- coding: utf-8 -*-
# Ghidra Jython 脚本：导出目标函数反编译
# 用法：analyzeHeadless ... -postScript ExportDecomp.py <输出目录> <rva1,rva2,...>
#@category teletalk

from ghidra.app.decompiler import DecompInterface, DecompileOptions
from ghidra.util.task import ConsoleTaskMonitor
import os, re, io

args = getScriptArgs()
if len(args) < 1:
    print("用法: ExportDecomp.py <输出目录> [rva1,rva2,...]")
    exit()

out_dir = args[0]
if len(args) >= 2 and args[1].strip():
    targets = [t.strip() for t in args[1].split(",") if t.strip()]
else:
    # 默认目标集（Windows .bat 传逗号参数会被吞，用内置表更可靠）
    targets = [
        "182380", "17fa30", "182d20", "f8c50",
        "169000", "16a850", "16b0d0", "16ce90",
        "16d3a0", "16d6e0", "16fb00", "176a10",
        "89e20", "81490", "168e60", "17a230",
    ]
if not os.path.isdir(out_dir):
    os.makedirs(out_dir)

base = currentProgram.getImageBase()
fm = currentProgram.getFunctionManager()

ifc = DecompInterface()
ifc.setOptions(DecompileOptions())
ifc.openProgram(currentProgram)
monitor = ConsoleTaskMonitor()


def write_utf8(path, text):
    fh = io.open(path, "w", encoding="utf-8")
    try:
        fh.write(unicode(text))
    finally:
        fh.close()


for t in targets:
    rva = int(t, 16)
    addr = base.add(rva)
    f = fm.getFunctionContaining(addr)
    if f is None:
        # Ghidra 未识别，用 getFunctionAt 或强制反汇编后创建
        try:
            disassemble(addr)
            f = createFunction(addr, None)
        except:
            f = None
        if f is None:
            f = fm.getFunctionAt(addr)
    if f is None:
        print("[missing] 0x%s" % t)
        continue

    res = ifc.decompileFunction(f, 180, monitor)
    lines = []
    lines.append(u"// RVA: 0x%s" % t)
    lines.append(u"// name: %s" % f.getName())
    lines.append(u"// entry: %s" % f.getEntryPoint())
    lines.append(u"// size: %d bytes" % f.getBody().getNumAddresses())
    callers = list(f.getCallingFunctions(monitor))
    lines.append(u"// callers: %d" % len(callers))
    lines.append(u"")
    if res.decompileCompleted():
        lines.append(res.getDecompiledFunction().getC())
    else:
        lines.append(u"// decompile failed: %s" % res.getErrorMessage())

    lines.append(u"")
    lines.append(u"// ===== callers =====")
    for c in callers:
        lines.append(u"//   %s @ %s" % (c.getName(), c.getEntryPoint()))

    name = re.sub(r"[^A-Za-z0-9_]", "_", f.getName())
    path = os.path.join(out_dir, "0x%s_%s.c" % (t, name))
    write_utf8(path, u"\n".join(lines))
    total = 0
    for x in lines:
        total += len(x)
    print("  wrote %s (%d chars)" % (os.path.basename(path), total))

ifc.dispose()
print("done")
