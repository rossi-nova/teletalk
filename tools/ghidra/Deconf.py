# -*- coding: utf-8 -*-
# 反编译 0x48D9D0（配置查询器）及 0x107000（配置解密后才调的）
#@category teletalk

from ghidra.app.decompiler import DecompInterface, DecompileOptions
from ghidra.util.task import ConsoleTaskMonitor
import os, re, io

args = getScriptArgs()
out_dir = args[0] if len(args) > 0 else ".ghidra/out/conf"

if not os.path.isdir(out_dir):
    os.makedirs(out_dir)

targets = [0x48d9d0, 0x107000, 0x107304]  # 配置查询、解密函数、调用处
base = currentProgram.getImageBase()
fm = currentProgram.getFunctionManager()
ifc = DecompInterface()
ifc.setOptions(DecompileOptions())
ifc.openProgram(currentProgram)
monitor = ConsoleTaskMonitor()

for t in targets:
    addr = base.add(t)
    f = fm.getFunctionContaining(addr)
    if f is None:
        try:
            createFunction(addr, None)
            f = fm.getFunctionContaining(addr)
        except:
            pass
    if f is None:
        print("[missing] 0x%x" % t)
        continue

    res = ifc.decompileFunction(f, 180, monitor)
    lines = []
    rva = f.getEntryPoint().subtract(base)
    lines.append(u"// RVA 0x%x  name: %s" % (rva, unicode(f.getName())))
    lines.append(u"// size: %d bytes" % f.getBody().getNumAddresses())
    lines.append(u"")
    if res.decompileCompleted():
        lines.append(res.getDecompiledFunction().getC())
    else:
        lines.append(u"// decompile failed: %s" % unicode(res.getErrorMessage()))

    name = re.sub(r"[^A-Za-z0-9_]", "_", f.getName())
    path = os.path.join(out_dir, "conf_0x%x_%s.c" % (rva, name))
    fh = io.open(path, "w", encoding="utf-8")
    try:
        fh.write(u"\n".join(lines))
    finally:
        fh.close()
    print("  wrote %s (%d chars)" % (os.path.basename(path), sum(len(x) for x in lines)))

ifc.dispose()
print("done")