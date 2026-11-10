// Prepare one exact linker extent in a disposable no-analysis Program copy.
import com.google.gson.Gson;
import ghidra.app.cmd.disassemble.DisassembleCommand;
import ghidra.app.util.headless.HeadlessScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.symbol.SourceType;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.MessageDigest;
import java.util.HexFormat;
import java.util.Map;

public class MacscopeFocus extends HeadlessScript {
    @Override
    public void run() throws Exception {
        String[] args = getScriptArgs();
        if (args.length != 5 || isHeadlessAnalysisEnabled() || !"12.2".equals(getGhidraVersion())
                || !args[1].equals(currentProgram.getExecutableSHA256())) {
            throw new IllegalStateException("Focused query requires the verified no-analysis import");
        }
        var space = currentProgram.getAddressFactory().getDefaultAddressSpace();
        Address start = space.getAddress(args[2].substring(2));
        Address end = space.getAddress(args[3].substring(2));
        long size = end.subtract(start);
        if (size < 1 || size > 8192 || start.compareTo(end) >= 0) {
            throw new IllegalStateException("Invalid focused linker extent");
        }
        byte[] bytes = new byte[(int) size];
        String digest = currentProgram.getMemory().getBytes(start, bytes) == bytes.length
            ? HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(bytes)) : "";
        if (!args[4].equals(digest)) {
            throw new IllegalStateException("Program extent bytes differ from the verified slice");
        }

        int transaction = currentProgram.startTransaction("Prepare selected linker extent");
        boolean prepared = false;
        try {
            var allowed = new AddressSet(start, end.subtract(1));
            new DisassembleCommand(start, allowed, true).applyTo(currentProgram, monitor);
            if (getInstructionAt(start) == null) {
                throw new IllegalStateException("Cannot disassemble the selected entry");
            }
            var body = new AddressSet();
            var instructions = currentProgram.getListing().getInstructions(allowed, true);
            while (instructions.hasNext()) {
                monitor.checkCancelled();
                var instruction = instructions.next();
                if (!allowed.contains(instruction.getMinAddress(), instruction.getMaxAddress())) {
                    throw new IllegalStateException("An instruction crosses the selected linker extent");
                }
                body.addRange(instruction.getMinAddress(), instruction.getMaxAddress());
            }
            var manager = currentProgram.getFunctionManager();
            var function = manager.getFunctionAt(start);
            if (function == null) {
                function = manager.createFunction(null, start, body, SourceType.USER_DEFINED);
            } else {
                function.setBody(body);
            }
            if (function == null || function.isExternal() || function.isThunk()) {
                throw new IllegalStateException("Cannot prepare a local function at the selected entry");
            }
            Files.writeString(Path.of(args[0]), new Gson().toJson(Map.of(
                "entry_va", args[2], "end_va_exclusive", args[3], "extent_sha256", digest)));
            prepared = true;
        } finally {
            // Retain the temporary definition for the post-script. Headless opens the copy read-only.
            currentProgram.endTransaction(transaction, prepared);
        }
    }
}
