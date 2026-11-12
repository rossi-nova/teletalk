# -*- coding: utf-8 -*-
# 找出引用指定数据地址的所有函数，并反编译它们
#
# 用法：FindRefs.py <输出目录> <rva1,rva2,...>
#@category teletalk

from ghidra.app.decompiler import DecompInterface, DecompileOptions
from ghidra.util.task import ConsoleTaskMonitor
import os, re, io

args = getScriptArgs()
if len(args) < 1:
    print("usage: FindRefs.py <outdir> [rva1,rva2,...]")
    exit()

out_dir = args[0]
if len(args) >= 2 and args[1].strip():
    targets = [int(t, 16) for t in args[1].split(",") if t.strip()]
else:
    targets = [0x8ff700]   # base64 表

if not os.path.isdir(out_dir):
    os.makedirs(out_dir)

base = currentProgram.getImageBase()
rm = currentProgram.getReferenceManager()
fm = currentProgram.getFunctionManager()

ifc = DecompInterface()
ifc.setOptions(DecompileOptions())
ifc.openProgram(currentProgram)
monitor = ConsoleTaskMonitor()

report = []

for t in targets:
    addr = base.add(t)
    print("=== target 0x%x ===" % t)
    report.append("=== target RVA 0x%x ===" % t)

    seen = set()
    for ref in rm.getReferencesTo(addr):
        frm = ref.getFromAddress()
        func = fm.getFunctionContaining(frm)
        if func is None:
            report.append("  [no func] ref from %s type=%s" % (frm, ref.getReferenceType()))
            continue
        key = str(func.getEntryPoint())
        if key in seen:
            continue
        seen.add(key)
        rva = func.getEntryPoint().subtract(base)
        report.append("  func %s @ RVA 0x%x  (ref from %s)" %
                      (func.getName(), rva, frm))
        print("  引用函数: %s @ 0x%x" % (func.getName(), rva))

        # 反编译
        res = ifc.decompileFunction(func, 120, monitor)
        lines = []
        lines.append("// RVA 0x%x  名 %s" % (rva, func.getName()))
        lines.append("// 大小 %d 字节" % func.getBody().getNumAddresses())
        lines.append("")
        if res.decompileCompleted():
            lines.append(res.getDecompiledFunction().getC())
        else:
            lines.append("// 反编译失败: %s" % res.getErrorMessage())
        name = re.sub(r"[^A-Za-z0-9_]", "_", func.getName())
        path = os.path.join(out_dir, "ref_0x%x_%s.c" % (rva, name))
        fh = io.open(path, "w", encoding="utf-8")
        try:
            fh.write(u"\n".join(lines))
        finally:
            fh.close()
        print("    -> %s" % os.path.basename(path))

ifc.dispose()

fh = io.open(os.path.join(out_dir, "refs.txt"), "w", encoding="utf-8")
try:
    fh.write(u"\n".join(report))
finally:
    fh.close()
print("done")
