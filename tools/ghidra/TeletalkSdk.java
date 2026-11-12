// Ghidra headless 总控脚本：一次性完成 SDK 分析
//
// 用法：
//   analyzeHeadless <projDir> <projName> -import <dll> -postScript TeletalkSdk.java <输出目录>
//
// 产出：
//   <输出目录>/summary.txt        函数清单（按大小排序）
//   <输出目录>/exports.txt        导出表
//   <输出目录>/vtables.txt        虚表候选（.rdata 中的函数指针数组）
//   <输出目录>/funcs/<rva>_<name>.c  指定函数的反编译
//   <输出目录>/strings.txt        可疑字符串
//
//@category teletalk

import ghidra.app.script.GhidraScript;
import ghidra.app.decompiler.*;
import ghidra.program.model.address.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.mem.*;
import ghidra.program.model.symbol.*;
import ghidra.program.model.data.*;
import java.io.*;
import java.util.*;

public class TeletalkSdk extends GhidraScript {

    /** 重点反编译的函数（RVA hex） */
    private static final String[] TARGETS = {
        "182380", // getSecurityToken
        "17fa30", // initUMID
        "182d20", // getCompatibelDcpToken
        "f8c50",  // QueryInterface
        "169000", "16a850", "16b0d0", "16ce90",
        "16d3a0", "16d6e0", "16fb00", "176a10", // ITrafficFilter 虚表
        "89e20", "81490", "168e60", "17a230",   // 签名路径关键
    };

    @Override
    public void run() throws Exception {
        String[] args = getScriptArgs();
        File outDir = new File(args.length > 0 ? args[0] : "teletalk-out");
        outDir.mkdirs();
        File funcDir = new File(outDir, "funcs");
        funcDir.mkdirs();

        println("输出目录: " + outDir.getAbsolutePath());
        println("程序: " + currentProgram.getName());
        println("ImageBase: " + currentProgram.getImageBase());

        FunctionManager fm = currentProgram.getFunctionManager();
        SymbolTable st = currentProgram.getSymbolTable();

        // ---- 1. 函数清单 ----
        List<Function> funcs = new ArrayList<>();
        for (Function f : fm.getFunctions(true)) funcs.add(f);
        funcs.sort((a, b) -> Long.compare(b.getBody().getNumAddresses(), a.getBody().getNumAddresses()));

        StringBuilder summary = new StringBuilder();
        summary.append("程序: ").append(currentProgram.getName()).append("\n");
        summary.append("ImageBase: ").append(currentProgram.getImageBase()).append("\n");
        summary.append("函数总数: ").append(funcs.size()).append("\n\n");
        summary.append("== 最大的 200 个函数 ==\n");
        summary.append("RVA\t大小\t名称\t调用者数\n");
        ReferenceManager rm = currentProgram.getReferenceManager();
        for (int i = 0; i < Math.min(200, funcs.size()); i++) {
            Function f = funcs.get(i);
            long rva = f.getEntryPoint().subtract(currentProgram.getImageBase());
            int refs = 0;
            for (Reference r : rm.getReferencesTo(f.getEntryPoint())) if (r.getReferenceType().isCall()) refs++;
            summary.append(String.format("0x%x\t%d\t%s\t%d\n", rva, f.getBody().getNumAddresses(), f.getName(), refs));
        }

        // ---- 2. 导出表 ----
        summary.append("\n== 导出 ==\n");
        for (Symbol s : st.getAllSymbols(true)) {
            if (s.isExternalEntryPoint()) {
                long rva = s.getAddress().subtract(currentProgram.getImageBase());
                summary.append(String.format("0x%x\t%s\n", rva, s.getName()));
            }
        }
        write(new File(outDir, "summary.txt"), summary.toString());

        // ---- 3. 重点函数反编译 ----
        DecompInterface ifc = new DecompInterface();
        ifc.setOptions(new DecompileOptions());
        ifc.openProgram(currentProgram);

        for (String t : TARGETS) {
            long rva = Long.parseLong(t, 16);
            Address addr = currentProgram.getImageBase().add(rva);
            Function f = fm.getFunctionContaining(addr);
            if (f == null) {
                summary.append("\n[缺失] 0x" + t + " 未被识别为函数\n");
                continue;
            }
            DecompileResults res = ifc.decompileFunction(f, 180, monitor);
            StringBuilder sb = new StringBuilder();
            sb.append("// RVA: 0x").append(t).append("\n");
            sb.append("// 名称: ").append(f.getName()).append("\n");
            sb.append("// 入口: ").append(f.getEntryPoint()).append("\n");
            sb.append("// 签名: ").append(f.getSignature()).append("\n");
            sb.append("// 大小: ").append(f.getBody().getNumAddresses()).append(" 字节\n");
            sb.append("// 调用者数: ").append(f.getCallingFunctions(monitor).size()).append("\n\n");

            if (res.decompileCompleted()) {
                sb.append(res.getDecompiledFunction().getC());
            } else {
                sb.append("// 反编译失败: ").append(res.getErrorMessage()).append("\n");
            }

            // 调用者清单
            sb.append("\n\n// ===== 调用者 =====\n");
            for (Function c : f.getCallingFunctions(monitor)) {
                sb.append("//   ").append(c.getName()).append(" @ ")
                  .append(c.getEntryPoint().subtract(currentProgram.getImageBase())).append("\n");
            }

            File out = new File(funcDir, "0x" + t + "_" + sanitize(f.getName()) + ".c");
            write(out, sb.toString());
            println("  反编译 " + t + " -> " + out.getName() + " (" + sb.length() + " 字符)");
        }
        ifc.dispose();

        write(new File(outDir, "summary.txt"), summary.toString());
        println("完成。见 " + outDir.getAbsolutePath());
    }

    private void write(File f, String s) throws IOException {
        try (PrintWriter pw = new PrintWriter(new OutputStreamWriter(new FileOutputStream(f), "UTF-8"))) {
            pw.print(s);
        }
    }

    private String sanitize(String s) {
        return s.replaceAll("[^A-Za-z0-9_]", "_");
    }
}
