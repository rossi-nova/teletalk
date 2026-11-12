// Ghidra headless 脚本：导出指定函数的反编译结果与引用
// 用法（postScript）：
//   ExportFuncDecomp.java <输出目录> <hex1,hex2,...>
// 示例：ExportFuncDecomp.java C:\out 182380,16fb00,89e20
//
//@category teletalk

import ghidra.app.script.GhidraScript;
import ghidra.app.decompiler.*;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionManager;
import ghidra.program.model.symbol.*;
import java.io.*;
import java.util.*;

public class ExportFuncDecomp extends GhidraScript {
    @Override
    public void run() throws Exception {
        String[] args = getScriptArgs();
        if (args.length < 2) {
            println("用法: ExportFuncDecomp <输出目录> <hex1,hex2,...>");
            return;
        }
        File outDir = new File(args[0]);
        outDir.mkdirs();
        String[] targets = args[1].split(",");

        DecompInterface ifc = new DecompInterface();
        DecompileOptions opts = new DecompileOptions();
        ifc.setOptions(opts);
        ifc.openProgram(currentProgram);
        ifc.setSimplificationStyle("decompile");

        FunctionManager fm = currentProgram.getFunctionManager();

        for (String t : targets) {
            long off = Long.parseLong(t.trim(), 16);
            Address addr = currentProgram.getImageBase().add(off);
            println("=== 目标 " + t + " => " + addr);

            // 先确保该地址被识别为函数
            Function f = fm.getFunctionContaining(addr);
            if (f == null) {
                try {
                    disassemble(addr);
                    f = createFunction(addr, null);
                    println("  创建函数: " + (f != null));
                } catch (Exception e) {
                    println("  创建函数失败: " + e.getMessage());
                }
            }
            if (f == null) {
                println("  未找到函数，跳过");
                continue;
            }

            String fname = String.format("%s_%s", t, sanitize(f.getName()));
            StringBuilder sb = new StringBuilder();
            sb.append("// 目标 RVA: 0x").append(t).append("\n");
            sb.append("// 函数: ").append(f.getName()).append("\n");
            sb.append("// 入口: ").append(f.getEntryPoint()).append("\n");
            sb.append("// 签名: ").append(f.getSignature()).append("\n");
            sb.append("// 大小: ").append(f.getBody().getNumAddresses()).append(" 字节\n\n");

            // 反编译
            DecompileResults res = ifc.decompileFunction(f, 120, monitor);
            if (res.decompileCompleted()) {
                sb.append(res.getDecompiledFunction().getC());
            } else {
                sb.append("// 反编译失败: ").append(res.getErrorMessage()).append("\n");
            }

            // 调用者
            sb.append("\n\n// ===== 调用者 =====\n");
            ReferenceIterator refs = currentProgram.getReferenceManager().getReferencesTo(f.getEntryPoint());
            Set<Address> seen = new HashSet<>();
            for (Reference r : refs) {
                if (r.getReferenceType().isCall() || r.getReferenceType().isJump()) {
                    Address from = r.getFromAddress();
                    if (!seen.add(from)) continue;
                    Function caller = fm.getFunctionContaining(from);
                    sb.append(String.format("//   %s  in %s\n", from,
                        caller == null ? "(无函数)" : caller.getName() + " @" + caller.getEntryPoint()));
                }
            }

            // 被调用目标（顶层）
            sb.append("\n// ===== 直接调用 =====\n");
            Set<String> callees = new TreeSet<>();
            for (Reference r : currentProgram.getReferenceManager().getReferencesFrom(f.getEntryPoint())) {
                // 略
            }
            // 用 body 扫引用
            ghidra.program.model.address.AddressIterator it = f.getBody().getAddresses(true);
            while (it.hasNext()) {
                Address a = it.next();
                for (Reference r : currentProgram.getReferenceManager().getReferencesFrom(a)) {
                    if (r.getReferenceType().isCall()) {
                        Function cf = fm.getFunctionAt(r.getToAddress());
                        callees.add(String.format("//   0x%s -> %s", r.getToAddress(),
                            cf == null ? "?" : cf.getName()));
                    }
                }
            }
            for (String s : callees) sb.append(s).append("\n");

            File out = new File(outDir, fname + ".c");
            try (PrintWriter pw = new PrintWriter(new FileWriter(out))) {
                pw.print(sb);
            }
            println("  已写出 " + out.getName() + " (" + sb.length() + " 字符)");
        }
        ifc.dispose();
        println("完成");
    }

    private String sanitize(String s) {
        return s.replaceAll("[^A-Za-z0-9_]", "_");
    }
}
