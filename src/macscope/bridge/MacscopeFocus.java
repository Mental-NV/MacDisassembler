// Prepare one exact linker extent in a disposable no-analysis Program copy.
import com.google.gson.Gson;
import com.google.gson.JsonArray;
import com.google.gson.JsonObject;
import com.google.gson.JsonParser;
import ghidra.app.cmd.disassemble.DisassembleCommand;
import ghidra.app.util.headless.HeadlessScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.symbol.SourceType;
import ghidra.program.model.listing.FlowOverride;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.MessageDigest;
import java.util.HexFormat;
import java.util.Map;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;

public class MacscopeFocus extends HeadlessScript {
    @Override
    public void run() throws Exception {
        String[] args = getScriptArgs();
        if (args.length != 7 || isHeadlessAnalysisEnabled() || !"12.2".equals(getGhidraVersion())
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

        Path request = Path.of(args[5]);
        if (Files.size(request) > 128 * 1024) throw new IllegalStateException("Unbounded tail-call proof");
        byte[] requestBytes = Files.readAllBytes(request);
        String requestDigest = HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(requestBytes));
        if (!requestDigest.equals(args[6])) throw new IllegalStateException("Tail-call request digest differs");
        JsonObject plan = JsonParser.parseString(new String(requestBytes, java.nio.charset.StandardCharsets.UTF_8)).getAsJsonObject();
        JsonArray candidates = plan.getAsJsonArray("candidates");
        if (!"macscope-focused-tail-calls/1".equals(plan.get("policy").getAsString()) || candidates.size() > 64 ||
            (candidates.size() > 0 && (!"arm64".equals(plan.get("arch").getAsString()) ||
             !"AARCH64:LE:64:AppleSilicon".equals(currentProgram.getLanguageID().getIdAsString())))) {
            throw new IllegalStateException("Tail-call proof architecture or bounds differ");
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
            JsonArray decisions = new JsonArray();
            Address previous = null;
            for (var element : candidates) {
                monitor.checkCancelled();
                JsonObject candidate = element.getAsJsonObject();
                Address source = space.getAddress(candidate.get("source_va").getAsString().substring(2));
                Address target = space.getAddress(candidate.get("target_va").getAsString().substring(2));
                String kind = candidate.get("target_kind").getAsString();
                byte[] raw = HexFormat.of().parseHex(candidate.get("source_bytes").getAsString());
                if (raw.length != 4 || source.getOffset() % 4 != 0 || !allowed.contains(source, source.add(3)) ||
                    allowed.contains(target) || previous != null && source.compareTo(previous) <= 0 ||
                    !(kind.equals("linker_function_start") || kind.equals("declared_import_stub"))) {
                    throw new IllegalStateException("Invalid tail-call source or destination");
                }
                previous = source;
                int word = ByteBuffer.wrap(raw).order(ByteOrder.LITTLE_ENDIAN).getInt();
                long displacement = ((long) (word << 6) >> 6) * 4;
                if ((word & 0xfc000000) != 0x14000000 || !source.addNoWrap(displacement).equals(target))
                    throw new IllegalStateException("Tail-call destination differs from branch bytes");
                byte[] memory = new byte[4];
                if (currentProgram.getMemory().getBytes(source, memory) != 4 || !java.util.Arrays.equals(raw, memory))
                    throw new IllegalStateException("Tail-call source bytes differ from Program");
                byte[] targetBytes = HexFormat.of().parseHex(candidate.get("target_bytes").getAsString());
                int targetSize = kind.equals("linker_function_start") ? 4 : 12;
                byte[] targetMemory = new byte[targetSize];
                if (targetBytes.length != targetSize || currentProgram.getMemory().getBytes(target, targetMemory) != targetSize ||
                    !java.util.Arrays.equals(targetBytes, targetMemory))
                    throw new IllegalStateException("Tail-call destination bytes differ from Program");
                var instruction = getInstructionAt(source);
                String outcome = "instruction_unavailable";
                if (instruction != null) {
                    var flows = instruction.getFlows();
                    if (instruction.getLength() != 4 || instruction.getFlowOverride() != FlowOverride.NONE ||
                        !"UNCONDITIONAL_JUMP".equals(instruction.getFlowType().toString()) ||
                        instruction.getFallThrough() != null || flows.length != 1 || !flows[0].equals(target) ||
                        !java.util.Arrays.equals(raw, instruction.getBytes())) {
                        throw new IllegalStateException("Native instruction disagrees with tail-call proof");
                    }
                    instruction.setFlowOverride(FlowOverride.CALL_RETURN);
                    if (!"CALL_TERMINATOR".equals(instruction.getFlowType().toString()))
                        throw new IllegalStateException("Native tail-call override was not applied");
                    outcome = "applied";
                }
                JsonObject decision = new JsonObject();
                decision.addProperty("source_va", candidate.get("source_va").getAsString());
                decision.addProperty("outcome", outcome);
                decisions.add(decision);
            }
            JsonObject recovery = new JsonObject();
            recovery.addProperty("policy", "macscope-focused-tail-calls/1");
            recovery.addProperty("request_sha256", requestDigest);
            recovery.add("decisions", decisions);
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
                "entry_va", args[2], "end_va_exclusive", args[3], "extent_sha256", digest, "tail_calls", recovery)));
            prepared = true;
        } finally {
            // Retain the temporary definition for the post-script. Headless opens the copy read-only.
            currentProgram.endTransaction(transaction, prepared);
        }
    }
}
