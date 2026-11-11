// Decode a selected byte range without autoanalysis, functions or a decompiler.
import com.google.gson.Gson;
import com.google.gson.JsonArray;
import com.google.gson.JsonObject;
import ghidra.app.util.PseudoDisassembler;
import ghidra.app.util.headless.HeadlessScript;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.MessageDigest;
import java.util.HexFormat;

public class MacscopeDisasm extends HeadlessScript {
    @Override public void run() throws Exception {
        String[] args = getScriptArgs();
        if (args.length != 6 || isHeadlessAnalysisEnabled() || !"12.2".equals(getGhidraVersion())
                || !args[1].equals(currentProgram.getExecutableSHA256()))
            throw new IllegalStateException("Verified no-analysis import required");
        String language = currentProgram.getLanguageID().getIdAsString();
        if (!(args[2].equals("arm64") && language.equals("AARCH64:LE:64:AppleSilicon") ||
              args[2].equals("x86_64") && language.equals("x86:LE:64:default")))
            throw new IllegalStateException("Unsupported or mismatched language");
        var space = currentProgram.getAddressFactory().getDefaultAddressSpace();
        var start = space.getAddress(args[3].substring(2));
        var end = space.getAddress(args[4].substring(2));
        long size = end.subtract(start);
        if (size < 1 || size > 4096 || start.compareTo(end) >= 0)
            throw new IllegalStateException("Invalid byte bounds");
        byte[] bytes = new byte[(int)size];
        if (currentProgram.getMemory().getBytes(start,bytes) != size)
            throw new IllegalStateException("Unavailable bytes");
        String hash = HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(bytes));
        if (!hash.equals(args[5])) throw new IllegalStateException("Range byte mismatch");
        JsonObject result = new JsonObject();
        result.addProperty("schema","macscope-import-disasm/1");
        result.addProperty("ghidra_version",getGhidraVersion());
        result.addProperty("slice_sha256",args[1]);
        result.addProperty("arch",args[2]);
        result.addProperty("start_va",args[3]);
        result.addProperty("end_va",args[4]);
        result.addProperty("range_sha256",hash);
        result.addProperty("autoanalysis",isHeadlessAnalysisEnabled());
        JsonObject runtime = new JsonObject();
        runtime.addProperty("home",System.getProperty("java.home"));
        runtime.addProperty("version",System.getProperty("java.runtime.version"));
        runtime.addProperty("arch",System.getProperty("os.arch"));
        result.add("java_runtime",runtime);
        JsonArray rows = new JsonArray(), gaps = new JsonArray();
        result.add("instructions",rows);
        result.add("gaps",gaps);
        var cursor = start;
        var decoder = new PseudoDisassembler(currentProgram);
        while (cursor.compareTo(end) < 0) {
            monitor.checkCancelled();
            String failure = null;
            try {
                // The byte-array overload uses a memory-less ByteMemBufferImpl.
                // Never let the decoder read beyond the caller-selected extent.
                byte[] remaining = java.util.Arrays.copyOfRange(bytes,(int)cursor.subtract(start),bytes.length);
                var instruction = decoder.disassemble(cursor,remaining);
                if (instruction == null || instruction.getLength() < 1) {
                    failure = "undecodable_or_unavailable";
                } else if (instruction.getMaxAddress().compareTo(end) >= 0) {
                    failure = "instruction_crosses_range_boundary";
                } else {
                    JsonObject row = new JsonObject();
                    row.addProperty("addr","0x"+Long.toUnsignedString(cursor.getOffset(),16));
                    row.addProperty("bytes",HexFormat.of().formatHex(instruction.getBytes()));
                    row.addProperty("mnemonic",instruction.getMnemonicString());
                    row.addProperty("text",instruction.toString());
                    rows.add(row);
                    cursor = cursor.addNoWrap(instruction.getLength());
                }
            } catch (Exception ex) {
                failure = "undecodable_or_unavailable";
            }
            if (failure != null) {
                JsonObject gap = new JsonObject();
                gap.addProperty("start_va","0x"+Long.toUnsignedString(cursor.getOffset(),16));
                gap.addProperty("end_va",args[4]);
                gap.addProperty("reason",failure);
                gaps.add(gap);
                break;
            }
        }
        String output = new Gson().toJson(result);
        if (output.length() > 4*1024*1024) throw new IllegalStateException("Output limit");
        Files.writeString(Path.of(args[0]),output);
    }
}
