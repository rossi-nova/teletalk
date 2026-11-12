// Ghidra headless 脚本：分析控制流展平（CFF）的状态变量映射
//
// SDK 的 getSecurityToken 等函数用 `mov eax, imm; xor eax, KEY; jmp rax` 做分发。
// 本脚本扫描指定函数体内所有此类分发点，解出 imm -> 目标地址 的映射表。
//
// 用法：CffMap.java <输出文件> <函数RVA hex>
//@category teletalk

import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.*;
import ghidra.program.model.scalar.Scalar;
import java.io.*;
import java.util.*;

public class CffMap extends GhidraScript {

    @Override
    public void run() throws Exception {
        String[] args = getScriptArgs();
        if (args.length < 2) {
            println("用法: CffMap <输出文件> <函数RVA hex>");
            return;
        }
        File outFile = new File(args[0]);
        long rva = Long.parseLong(args[1], 16);
        Address entry = currentProgram.getImageBase().add(rva);

        Function f = getFunctionContaining(entry);
        if (f == null) {
            println("未找到函数 @ " + entry);
            return;
        }
        println("函数: " + f.getName() + " @ " + f.getEntryPoint()
            + " 大小 " + f.getBody().getNumAddresses());

        StringBuilder out = new StringBuilder();
        out.append("# CFF 分发点映射: ").append(f.getName()).append("\n");
        out.append("# 入口 RVA: 0x").append(args[1]).append("\n\n");

        Listing listing = currentProgram.getListing();
        InstructionIterator it = listing.getInstructions(f.getBody(), true);

        // 统计：上次 mov imm 的寄存器/值，用于 xor 配对
        Map<String, Long> lastImm = new HashMap<>();
        int dispatchCount = 0;
        Map<Long, List<String>> byKey = new TreeMap<>();

        while (it.hasNext()) {
            Instruction ins = it.next();
            String mnem = ins.getMnemonicString().toLowerCase();

            // mov reg, imm
            if (mnem.equals("mov") && ins.getNumOperands() == 2) {
                Object op0 = ins.getOpObjects(0).length > 0 ? ins.getOpObjects(0)[0] : null;
                Object[] op1 = ins.getOpObjects(1);
                if (op0 instanceof ghidra.program.model.lang.Register && op1.length == 1 && op1[0] instanceof Scalar) {
                    String reg = ((ghidra.program.model.lang.Register) op0).getName();
                    lastImm.put(reg, ((Scalar) op1[0]).getSignedValue());
                }
            }

            // xor reg, imm  —— 记录密钥
            if (mnem.equals("xor") && ins.getNumOperands() == 2) {
                Object[] op0 = ins.getOpObjects(0);
                Object[] op1 = ins.getOpObjects(1);
                if (op0.length == 1 && op0[0] instanceof ghidra.program.model.lang.Register
                    && op1.length == 1 && op1[0] instanceof Scalar) {
                    String reg = ((ghidra.program.model.lang.Register) op0[0]).getName();
                    long key = ((Scalar) op1[0]).getSignedValue();
                    Long prev = lastImm.get(reg);
                    byKey.computeIfAbsent(key, k -> new ArrayList<>())
                        .add(String.format("  @%s  key=0x%x  prevImm=0x%x", ins.getAddress(), key, prev == null ? -1 : prev));
                }
            }

            // jmp reg（间接跳转 = 分发点）
            if ((mnem.equals("jmp") || mnem.equals("jmpq")) && ins.getNumOperands() == 1) {
                Object[] op = ins.getOpObjects(0);
                if (op.length == 1 && op[0] instanceof ghidra.program.model.lang.Register) {
                    dispatchCount++;
                    String reg = ((ghidra.program.model.lang.Register) op[0]).getName();
                    out.append(String.format("JMP_INDIRECT 0x%s  reg=%s\n", ins.getAddress(), reg));
                }
            }
            // jmp [mem] 也算
            if ((mnem.equals("jmp") || mnem.equals("jmpq")) && ins.getNumOperands() == 1) {
                Object[] op = ins.getOpObjects(0);
                if (op.length == 1 && op[0] instanceof ghidra.program.model.scalar.Scalar) {
                    // 直接跳转，忽略
                } else if (op.length == 0 || !(op[0] instanceof ghidra.program.model.scalar.Scalar)) {
                    dispatchCount += 0;
                }
            }
        }

        out.append("\n## XOR 密钥统计（按密钥分组）\n");
        for (Map.Entry<Long, List<String>> e : byKey.entrySet()) {
            out.append(String.format("\nKEY 0x%x  （%d 处）\n", e.getKey(), e.getValue().size()));
            int n = 0;
            for (String s : e.getValue()) {
                if (n++ >= 40) { out.append("  ...\n"); break; }
                out.append(s).append("\n");
            }
        }
        out.append("\n合计间接跳转分发点: ").append(dispatchCount).append("\n");

        try (PrintWriter pw = new PrintWriter(new FileWriter(outFile))) {
            pw.print(out);
        }
        println("已写出 " + outFile.getAbsolutePath());
        println("分发点 " + dispatchCount + " 个，XOR 密钥 " + byKey.size() + " 种");
    }
}
