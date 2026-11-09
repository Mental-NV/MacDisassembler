// MacscopeBaseline.java — direct headless baseline exporter (Phase 1).
//
// Runs as an analyzeHeadless -postScript AFTER auto-analysis. Enumerates
// every function the engine derived from the binary alone, and exports per
// function: entry/body ranges, assembly with bytes, bounded pseudocode via
// DecompInterface, basic-block CFG evidence, and typed xref evidence, plus
// program-level identities (actual language/compiler IDs, sections,
// imports/exports). Each function carries its own status; a batch with one
// failure never looks like full success.
//
// Usage:
//   analyzeHeadless <projloc> <proj> -import <binary> \
//     -postScript MacscopeBaseline.java <output.json> <maxFuncs> <decompileTimeoutSecs> \
//     -scriptPath <repo>/analysis/scripts -max-cpu 4 -analysisTimeoutPerFile 600
//
// Binary-only hygiene (enforced by the runner, recorded here):
//   * analyst input dirs contain ONLY the target binary (no dSYM, no source,
//     no link maps); no -librarySearchPaths, no network symbol lookup,
//     scriptPath points at the repo scripts dir, never at analyst input.
//   * This script performs no network/file access beyond writing its output.
//   * No sandbox is claimed: the runner documents the isolation gap.
//
// Ghidra public APIs only: FunctionManager, Listing, DecompInterface,
// BasicBlockModel, ReferenceManager, Memory, SymbolTable.
import java.io.File;
import java.io.FileWriter;
import java.io.PrintWriter;
import java.util.ArrayList;
import java.util.List;

import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileOptions;
import ghidra.app.decompiler.DecompileResults;
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressRange;
import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.block.BasicBlockModel;
import ghidra.program.model.block.CodeBlock;
import ghidra.program.model.block.CodeBlockReferenceIterator;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionIterator;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.InstructionIterator;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.model.symbol.ExternalLocation;
import ghidra.program.model.symbol.Reference;
import ghidra.program.model.symbol.ReferenceIterator;
import ghidra.program.model.symbol.Symbol;
import ghidra.program.model.symbol.SymbolTable;

public class MacscopeBaseline extends GhidraScript {

    static final int MAX_INSTRUCTIONS = 2000;
    static final int MAX_XREFS_FROM = 200;
    static final int MAX_XREFS_TO = 200;
    static final int MAX_BLOCKS = 500;

    PrintWriter out;
    boolean firstFunction = true;
    int attempted = 0;
    int completed = 0;
    int timedOut = 0;
    int failed = 0;
    int notRequested = 0;

    @Override
    public void run() throws Exception {
        String[] args = getScriptArgs();
        if (args.length < 3) {
            printerr("Usage: MacscopeBaseline.java <output.json> <maxFuncs> <decompileTimeoutSecs>");
            return;
        }
        String outputPath = args[0];
        int maxFuncs = Integer.parseInt(args[1]);
        int decompileTimeoutSecs = Integer.parseInt(args[2]);

        Program program = currentProgram;
        File f = new File(outputPath);
        f.getParentFile().mkdirs();
        out = new PrintWriter(new FileWriter(f));

        out.println("{");
        jsonKV("schema", "macscope-baseline/1", true);
        jsonKV("tool", "MacscopeBaseline.java (direct analyzeHeadless post script)", true);
        jsonKV("ghidra_version", getGhidraVersion(), true);
        jsonKV("input_name", program.getName(), true);
        jsonKV("executable_md5", program.getExecutableMD5() == null ? "" : program.getExecutableMD5(), true);
        jsonKV("language_id", program.getLanguage().getLanguageID().getIdAsString(), true);
        jsonKV("compiler_spec_id", program.getCompilerSpec().getCompilerSpecID().getIdAsString(), true);
        jsonKV("image_base", program.getImageBase().toString(), true);
        jsonKV("min_address", program.getMinAddress().toString(), true);
        jsonKV("max_address", program.getMaxAddress().toString(), true);
        jsonKV("max_funcs", Integer.toString(maxFuncs), true);
        jsonKV("decompile_timeout_secs", Integer.toString(decompileTimeoutSecs), true);

        writeMemoryBlocks(program);
        writeImportsExports(program);

        List<Function> funcs = new ArrayList<>();
        FunctionIterator it = program.getFunctionManager().getFunctions(true);
        while (it.hasNext() && funcs.size() < maxFuncs) {
            funcs.add(it.next());
        }
        jsonKV("function_count_total_reported_by_engine",
            Long.toString(program.getFunctionManager().getFunctionCount()), true);
        jsonKV("function_count_enumerated", Integer.toString(funcs.size()), true);
        out.println("\"functions\": [");

        DecompInterface decomp = new DecompInterface();
        DecompileOptions opts = new DecompileOptions();
        decomp.setOptions(opts);
        boolean decompOpen = decomp.openProgram(program);
        BasicBlockModel blockModel = new BasicBlockModel(program);

        for (Function func : funcs) {
            writeFunction(program, func, blockModel, decompOpen ? decomp : null,
                decompileTimeoutSecs);
        }
        if (decompOpen) {
            decomp.dispose();
        }
        out.println("],");
        jsonKV("decompile_summary_attempted", Integer.toString(attempted), true);
        jsonKV("decompile_summary_completed", Integer.toString(completed), true);
        jsonKV("decompile_summary_timed_out", Integer.toString(timedOut), true);
        jsonKV("decompile_summary_failed", Integer.toString(failed), true);
        jsonKV("decompile_summary_not_requested", Integer.toString(notRequested), false);
        out.println("}");
        out.close();
        println("MacscopeBaseline: enumerated=" + funcs.size() + " completed=" + completed
            + " timedOut=" + timedOut + " failed=" + failed + " notRequested=" + notRequested);
    }

    void writeFunction(Program program, Function func, BasicBlockModel blockModel,
            DecompInterface decomp, int timeoutSecs) throws Exception {
        if (!firstFunction) {
            out.println(",");
        }
        firstFunction = false;
        out.println("  {");
        String status;
        String pseudocode = null;
        String decompError = "";
        if (func.isExternal() || func.isThunk()) {
            status = "not_requested";
            decompError = func.isExternal() ? "external (no body in image)"
                : "thunk (forwards to another function)";
            notRequested++;
        } else {
            attempted++;
            try {
                DecompileResults res = decomp.decompileFunction(func, timeoutSecs, monitor);
                if (res != null && res.decompileCompleted()) {
                    pseudocode = res.getDecompiledFunction().getC();
                    status = "complete";
                    completed++;
                } else {
                    status = "timeout";
                    decompError = res == null ? "null DecompileResults"
                        : ("decompileCompleted=false: " + res.getErrorMessage());
                    timedOut++;
                }
            } catch (Exception e) {
                status = "failed";
                decompError = e.getClass().getSimpleName() + ": " + e.getMessage();
                failed++;
            }
        }
        jsonKV("name", func.getName(), true, "    ");
        jsonKV("namespace", func.getParentNamespace().getName(), true, "    ");
        jsonKV("entry_va", "0x" + func.getEntryPoint().toString(), true, "    ");
        jsonKV("is_external", Boolean.toString(func.isExternal()), true, "    ");
        jsonKV("is_thunk", Boolean.toString(func.isThunk()), true, "    ");
        try {
            jsonKV("signature", func.getSignature(false).toString(), true, "    ");
        } catch (Exception e) {
            jsonKV("signature", "", true, "    ");
        }
        try {
            jsonKV("calling_convention", func.getCallingConventionName() == null ? ""
                : func.getCallingConventionName(), true, "    ");
        } catch (Exception e) {
            jsonKV("calling_convention", "", true, "    ");
        }
        // Body ranges.
        StringBuilder ranges = new StringBuilder("[");
        boolean first = true;
        try {
            for (AddressRange r : func.getBody()) {
                if (!first) ranges.append(",");
                first = false;
                ranges.append("[\"0x").append(r.getMinAddress().toString()).append("\",\"0x")
                    .append(r.getMaxAddress().toString()).append("\"]");
            }
        } catch (Exception e) {
            // leave empty; status below covers listing separately
        }
        ranges.append("]");
        out.println("    \"body_ranges\": " + ranges + ",");
        writeInstructions(program, func);
        writeCFG(program, func, blockModel);
        writeXrefs(program, func);
        jsonKV("decompile_status", status, true, "    ");
        jsonKV("decompile_error", decompError, true, "    ");
        if (pseudocode == null) {
            out.println("    \"pseudocode\": null");
        } else {
            out.println("    \"pseudocode\": " + q(pseudocode));
        }
        out.print("  }");
    }

    void writeInstructions(Program program, Function func) throws Exception {
        int count = 0;
        boolean truncated = false;
        StringBuilder sb = new StringBuilder("[");
        boolean first = true;
        try {
            AddressSetView body = func.getBody();
            InstructionIterator insns =
                program.getListing().getInstructions(body, true);
            while (insns.hasNext()) {
                if (count >= MAX_INSTRUCTIONS) {
                    truncated = true;
                    break;
                }
                Instruction ins = insns.next();
                if (!first) sb.append(",");
                first = false;
                sb.append("{\"addr\":\"0x").append(ins.getAddress().toString()).append("\",");
                sb.append("\"bytes\":\"").append(bytesHex(ins.getBytes())).append("\",");
                sb.append("\"text\":").append(q(ins.toString())).append(",");
                sb.append("\"flow\":").append(q(ins.getFlowType().toString())).append("}");
                count++;
            }
        } catch (Exception e) {
            truncated = true;
        }
        sb.append("]");
        out.println("    \"instruction_count\": " + count + ",");
        jsonKV("instructions_truncated", Boolean.toString(truncated), true, "    ");
        out.println("    \"instructions\": " + sb + ",");
    }

    void writeCFG(Program program, Function func, BasicBlockModel blockModel) {
        int blockCount = 0;
        boolean truncated = false;
        StringBuilder sb = new StringBuilder("[");
        boolean first = true;
        String cfgError = "";
        try {
            ghidra.program.model.block.CodeBlockIterator blockIter =
                blockModel.getCodeBlocksContaining(func.getBody(), monitor);
            while (blockIter.hasNext()) {
                CodeBlock b = blockIter.next();
                if (blockCount >= MAX_BLOCKS) {
                    truncated = true;
                    break;
                }
                if (!first) sb.append(",");
                first = false;
                sb.append("{\"min\":\"0x").append(b.getMinAddress().toString())
                    .append("\",\"max\":\"0x").append(b.getMaxAddress().toString())
                    .append("\",\"dsts\":[");
                boolean fdst = true;
                CodeBlockReferenceIterator dit = b.getDestinations(monitor);
                while (dit.hasNext()) {
                    ghidra.program.model.block.CodeBlockReference ref = dit.next();
                    if (!fdst) sb.append(",");
                    fdst = false;
                    sb.append("{\"to\":\"0x")
                        .append(ref.getDestinationAddress().toString()).append("\",")
                        .append("\"flow\":").append(q(ref.getFlowType().toString()))
                        .append("}");
                }
                sb.append("]}");
                blockCount++;
            }
        } catch (Exception e) {
            cfgError = e.getClass().getSimpleName() + ": " + e.getMessage();
        }
        sb.append("]");
        out.println("    \"block_count\": " + blockCount + ",");
        jsonKV("blocks_truncated", Boolean.toString(truncated), true, "    ");
        jsonKV("cfg_error", cfgError, true, "    ");
        out.println("    \"blocks\": " + sb + ",");
    }

    void writeXrefs(Program program, Function func) {
        // References TO the entry (callers).
        int toCount = 0;
        boolean toTrunc = false;
        StringBuilder to = new StringBuilder("[");
        boolean first = true;
        try {
            ReferenceIterator rit =
                program.getReferenceManager().getReferencesTo(func.getEntryPoint());
            while (rit.hasNext()) {
                if (toCount >= MAX_XREFS_TO) {
                    toTrunc = true;
                    break;
                }
                Reference r = rit.next();
                if (!first) to.append(",");
                first = false;
                to.append("{\"from\":\"0x").append(r.getFromAddress().toString())
                    .append("\",\"type\":").append(q(r.getReferenceType().toString()))
                    .append(",\"from_external\":")
                    .append(Boolean.toString(r.getFromAddress().isExternalAddress()))
                    .append("}");
                toCount++;
            }
        } catch (Exception e) {
            // keep partial
        }
        to.append("]");
        // Code/data references FROM instructions (bounded sample + total).
        int fromCount = 0;
        boolean fromTrunc = false;
        int fromTotal = 0;
        StringBuilder from = new StringBuilder("[");
        first = true;
        try {
            InstructionIterator insns =
                program.getListing().getInstructions(func.getBody(), true);
            while (insns.hasNext()) {
                Instruction ins = insns.next();
                for (Reference r : ins.getReferencesFrom()) {
                    fromTotal++;
                    if (fromCount >= MAX_XREFS_FROM) {
                        fromTrunc = true;
                        continue;
                    }
                    if (!first) from.append(",");
                    first = false;
                    from.append("{\"from\":\"0x").append(r.getFromAddress().toString())
                        .append("\",\"to\":\"0x").append(r.getToAddress().toString())
                        .append("\",\"type\":").append(q(r.getReferenceType().toString()))
                        .append("}");
                    fromCount++;
                }
            }
        } catch (Exception e) {
            // keep partial
        }
        from.append("]");
        out.println("    \"xrefs_to_entry_count\": " + toCount + ",");
        jsonKV("xrefs_to_entry_truncated", Boolean.toString(toTrunc), true, "    ");
        out.println("    \"xrefs_to_entry\": " + to + ",");
        out.println("    \"xrefs_from_sampled\": " + fromCount + ",");
        out.println("    \"xrefs_from_total\": " + fromTotal + ",");
        jsonKV("xrefs_from_truncated", Boolean.toString(fromTrunc), true, "    ");
        out.println("    \"xrefs_from_sample\": " + from + ",");
    }

    void writeMemoryBlocks(Program program) {
        StringBuilder sb = new StringBuilder("[");
        boolean first = true;
        Memory mem = program.getMemory();
        for (MemoryBlock b : mem.getBlocks()) {
            if (!first) sb.append(",");
            first = false;
            sb.append("{\"name\":").append(q(b.getName())).append(",");
            sb.append("\"start\":\"0x").append(b.getStart().toString()).append("\",");
            sb.append("\"end\":\"0x").append(b.getEnd().toString()).append("\",");
            sb.append("\"r\":").append(b.isRead() ? "true" : "false").append(",");
            sb.append("\"w\":").append(b.isWrite() ? "true" : "false").append(",");
            sb.append("\"x\":").append(b.isExecute() ? "true" : "false").append(",");
            sb.append("\"loaded\":").append(b.isLoaded() ? "true" : "false").append(",");
            sb.append("\"source\":").append(q(b.getSourceName() == null ? "" : b.getSourceName()));
            sb.append("}");
        }
        sb.append("]");
        out.println("\"sections\": " + sb + ",");
    }

    void writeImportsExports(Program program) {
        SymbolTable st = program.getSymbolTable();
        int impCount = 0;
        StringBuilder imp = new StringBuilder("[");
        boolean first = true;
        for (ghidra.program.model.symbol.SymbolIterator sii = st.getAllSymbols(false);
            sii.hasNext();) {
            Symbol s = sii.next();
            if (s.isExternal()) {
                if (impCount >= 500) break;
                ExternalLocation ext = null;
                try {
                    ext = (ExternalLocation) s.getObject();
                } catch (Exception e) {
                    ext = null;
                }
                if (!first) imp.append(",");
                first = false;
                imp.append("{\"name\":").append(q(s.getName())).append(",");
                imp.append("\"library\":")
                    .append(q(ext == null || ext.getLibraryName() == null ? ""
                        : ext.getLibraryName()));
                imp.append("}");
                impCount++;
            }
        }
        imp.append("]");
        out.println("\"external_symbol_sample_count\": " + impCount + ",");
        out.println("\"external_symbol_sample\": " + imp + ",");
    }

    // ---- JSON helpers ----
    static String q(String s) {
        if (s == null) return "null";
        StringBuilder b = new StringBuilder("\"");
        for (int i = 0; i < s.length(); i++) {
            char c = s.charAt(i);
            switch (c) {
                case '"': b.append("\\\""); break;
                case '\\': b.append("\\\\"); break;
                case '\n': b.append("\\n"); break;
                case '\r': b.append("\\r"); break;
                case '\t': b.append("\\t"); break;
                default:
                    if (c < 0x20) b.append(String.format("\\u%04x", (int) c));
                    else b.append(c);
            }
        }
        b.append("\"");
        return b.toString();
    }

    static String bytesHex(byte[] bytes) {
        StringBuilder b = new StringBuilder();
        for (byte x : bytes) b.append(String.format("%02x", x & 0xff));
        return b.toString();
    }

    void jsonKV(String k, String v, boolean comma) {
        out.println("\"" + k + "\": " + q(v) + (comma ? "," : ""));
    }

    void jsonKV(String k, String v, boolean comma, String indent) {
        out.println(indent + "\"" + k + "\": " + q(v) + (comma ? "," : ""));
    }
}
