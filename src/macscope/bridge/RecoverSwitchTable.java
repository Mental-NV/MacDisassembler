import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashSet;
import java.util.HexFormat;
import java.util.List;
import java.util.TreeSet;
import com.google.gson.Gson;
import com.google.gson.JsonArray;
import com.google.gson.JsonObject;
import com.google.gson.JsonParser;
import ghidra.app.cmd.disassemble.DisassembleCommand;
import ghidra.app.cmd.function.CreateFunctionCmd;
import ghidra.app.decompiler.DecompInterface;
import ghidra.app.util.headless.HeadlessScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Parameter;
import ghidra.program.model.pcode.FunctionPrototype;
import ghidra.program.model.pcode.JumpTable;
import ghidra.program.model.symbol.RefType;
import ghidra.program.model.symbol.SourceType;

public class RecoverSwitchTable extends HeadlessScript {
    static final String POLICY = "macscope-guarded-switch-table/1";

    @Override
    public void run() throws Exception {
        String[] args = getScriptArgs();
        if (args.length != 3 || isHeadlessAnalysisEnabled())
            throw new IllegalArgumentException("Expected a saved Program and switch proof");
        int timeout = Integer.parseInt(args[2]);
        Path request = Path.of(args[0]);
        if (timeout < 1 || timeout > 300 || Files.size(request) > 256 * 1024)
            throw new IllegalArgumentException("Unbounded switch proof");
        JsonObject plan = JsonParser.parseString(Files.readString(request)).getAsJsonObject();
        JsonArray rows = plan.getAsJsonArray("requests");
        if (!POLICY.equals(text(plan, "policy")) || rows.size() != 1 ||
            !"x86:LE:64:default".equals(currentProgram.getLanguageID().getIdAsString()) ||
            !text(plan, "image_sha256").equalsIgnoreCase(currentProgram.getExecutableSHA256()))
            throw new IllegalArgumentException("Switch proof differs from the saved Program");

        JsonObject row = rows.get(0).getAsJsonObject();
        Address entry = address(plan, "entry_va"), jump = address(row, "jump_va");
        Address jumpEnd = address(row, "jump_end_va"), fallback = address(row, "default_va");
        Address end = address(row, "end_va"), table = address(row, "table_va");
        Function root = getFunctionAt(entry);
        var oldBody = new AddressSet(entry, jumpEnd);
        oldBody.add(fallback, end);
        var gap = new AddressSet(jumpEnd.add(1), fallback.subtract(1));
        if (root == null || root.isExternal() || root.isThunk() ||
            end.subtract(entry) >= 8192 || jumpEnd.subtract(jump) != 1 ||
            gap.isEmpty() || !new AddressSet(root.getBody()).equals(oldBody) ||
            currentProgram.getFunctionManager().getFunctions(gap, true).hasNext())
            throw new IllegalStateException("Unverified switch body");
        checkKnownBytes(root, row.getAsJsonArray("known"));
        checkMemory(gap.getMinAddress(), text(row, "gap_bytes"), (int) gap.getNumAddresses());
        checkGuard(address(row, "guard_va"), jump, fallback);
        noIncoming(new AddressSet(entry.add(1), fallback.subtract(1)));

        ArrayList<Address> targets = tableTargets(row, table, gap, fallback);
        TreeSet<Address> starts = new TreeSet<>(targets);
        starts.remove(fallback);
        Address join = null;
        for (Address start : starts) {
            monitor.checkCancelled();
            Address next = starts.higher(start);
            if (next == null) next = fallback;
            Address observed = checkCase(start, next, entry, fallback, end);
            if (join == null) join = observed;
            else if (!join.equals(observed)) throw new IllegalStateException("Switch case exits disagree");
        }
        var refs = currentProgram.getReferenceManager();
        for (Address target : new HashSet<>(targets))
            refs.addMemoryReference(jump, target, RefType.COMPUTED_JUMP, SourceType.ANALYSIS, 0);
        CreateFunctionCmd.fixupFunctionBody(currentProgram, root, monitor);
        if (!new AddressSet(root.getBody()).equals(new AddressSet(entry, end)))
            throw new IllegalStateException("Recovered switch changed the function bounds");

        new JumpTable(jump, targets, true, 0).writeOverride(root);
        SourceType savedSource = root.getSignatureSource();
        Parameter[] savedParameters = root.getParameters();
        boolean tryRefresh = savedSource == SourceType.ANALYSIS && !root.hasCustomVariableStorage() &&
            !root.hasVarArgs() && inferred(root.getReturn().getSource()) &&
            Arrays.stream(savedParameters).allMatch(param -> inferred(param.getSource()));
        NativeSwitch observed = verifyNative(root, jump, targets, timeout);
        boolean refreshed = false;
        if (tryRefresh) {
            // Parameters inferred before the switch body was reachable can be missing.
            root.setSignatureSource(SourceType.DEFAULT);
            try {
                NativeSwitch candidate = verifyNative(root, jump, targets, timeout);
                refreshed = addsRegisterParameters(savedParameters, candidate.prototype());
                if (refreshed) observed = candidate;
            } catch (IllegalStateException error) {
                monitor.checkCancelled();
                println("Switch prototype refresh skipped: " + error.getMessage());
            } finally {
                if (!refreshed) root.setSignatureSource(savedSource);
            }
        }

        JsonObject prototype = new JsonObject();
        prototype.addProperty("saved_source", savedSource.name());
        prototype.addProperty("saved_parameter_count", savedParameters.length);
        prototype.addProperty("native_parameter_count", observed.prototype().getNumParams());
        prototype.addProperty("refreshed", refreshed);
        JsonObject report = new JsonObject();
        report.addProperty("policy", POLICY);
        report.add("entry_va", plan.get("entry_va"));
        for (String key : List.of("jump_va", "jump_end_va", "table_va", "targets"))
            report.add(key, row.get(key));
        report.add("labels", observed.labels());
        report.add("prototype", prototype);
        report.addProperty("status", "applied");
        Files.writeString(Path.of(args[1]), new Gson().toJson(report),
            StandardOpenOption.CREATE_NEW, StandardOpenOption.WRITE);
    }

    void checkKnownBytes(Function function, JsonArray rows) throws Exception {
        var instructions = currentProgram.getListing().getInstructions(function.getBody(), true);
        for (var element : rows) {
            monitor.checkCancelled();
            JsonObject row = element.getAsJsonObject();
            if (!instructions.hasNext()) throw new IllegalStateException("Incomplete saved switch");
            var instruction = instructions.next();
            if (!instruction.getAddress().equals(address(row, "va")) ||
                !Arrays.equals(instruction.getBytes(), HexFormat.of().parseHex(text(row, "bytes"))))
                throw new IllegalStateException("Switch instruction differs from the proved bytes");
        }
        if (instructions.hasNext()) throw new IllegalStateException("Incomplete switch byte proof");
    }

    void checkGuard(Address guard, Address jump, Address fallback) {
        var branch = getInstructionAt(guard);
        var computed = getInstructionAt(jump);
        if (branch == null || !branch.getFlowType().isConditional() || !branch.getFlowType().isJump() ||
            !Arrays.equals(branch.getFlows(), new Address[] {fallback}) ||
            computed == null || computed.getFlowType() != RefType.COMPUTED_JUMP ||
            computed.getFlows().length != 0)
            throw new IllegalStateException("Saved guard or computed jump differs from the proof");
    }

    void noIncoming(AddressSet interval) throws Exception {
        var refs = currentProgram.getReferenceManager();
        var destinations = refs.getReferenceDestinationIterator(interval, true);
        int inspected = 0;
        while (destinations.hasNext()) {
            monitor.checkCancelled();
            var incoming = refs.getReferencesTo(destinations.next());
            while (incoming.hasNext()) {
                if (++inspected > 4096 || incoming.next().getReferenceType().isFlow())
                    throw new IllegalStateException("Unexpected control-flow reference into switch interval");
            }
        }
    }

    ArrayList<Address> tableTargets(JsonObject row, Address table, AddressSet gap, Address fallback) throws Exception {
        JsonArray entries = row.getAsJsonArray("targets");
        if (entries.size() < 2 || entries.size() > 64)
            throw new IllegalStateException("Unbounded switch table");
        byte[] bytes = checkMemory(table, text(row, "table_bytes"), 4 * entries.size());
        ByteBuffer data = ByteBuffer.wrap(bytes).order(ByteOrder.LITTLE_ENDIAN);
        ArrayList<Address> targets = new ArrayList<>();
        for (var entry : entries) {
            Address target = table.add(data.getInt());
            if (!target.equals(address(entry.getAsString())) || !gap.contains(target) && !target.equals(fallback))
                throw new IllegalStateException("Unverified switch destination");
            targets.add(target);
        }
        return targets;
    }

    byte[] checkMemory(Address address, String hex, int size) throws Exception {
        byte[] expected = HexFormat.of().parseHex(hex);
        byte[] actual = new byte[size];
        if (expected.length != size || currentProgram.getMemory().getBytes(address, actual) != size ||
            !Arrays.equals(expected, actual))
            throw new IllegalStateException("Saved switch bytes differ from the proof at " + address);
        return actual;
    }

    Address checkCase(Address start, Address next, Address entry, Address fallback, Address end) throws Exception {
        if (getInstructionAt(start) == null &&
            !new DisassembleCommand(start, new AddressSet(start, next.subtract(1)), true).applyTo(currentProgram, monitor))
            throw new IllegalStateException("Cannot disassemble verified switch case");
        Address address = start;
        while (address.compareTo(next) < 0) {
            monitor.checkCancelled();
            var instruction = getInstructionAt(address);
            if (instruction == null || currentProgram.getFunctionManager().getFunctionContaining(address) != null)
                throw new IllegalStateException("Switch case belongs to another function");
            var flow = instruction.getFlowType();
            Address following = address.add(instruction.getLength());
            if (following.equals(next)) {
                Address[] destinations = instruction.getFlows();
                if (flow != RefType.UNCONDITIONAL_JUMP || destinations.length != 1 ||
                    destinations[0].compareTo(fallback) <= 0 || destinations[0].compareTo(end) > 0 ||
                    getInstructionAt(destinations[0]) == null)
                    throw new IllegalStateException("Switch case has no bounded join");
                return destinations[0];
            }
            if (flow.isComputed() || flow.isTerminal() || flow.isJump() ||
                !following.equals(instruction.getFallThrough()))
                throw new IllegalStateException("Unexpected flow inside switch case");
            if (flow.isCall()) {
                Address[] destinations = instruction.getFlows();
                if (destinations.length != 1 || destinations[0].equals(entry) || getFunctionAt(destinations[0]) == null)
                    throw new IllegalStateException("Switch case call has no separate function entry");
            }
            address = following;
        }
        throw new IllegalStateException("Switch case crosses its proved bound");
    }

    boolean inferred(SourceType source) {
        return source == SourceType.DEFAULT || source == SourceType.ANALYSIS;
    }

    boolean addsRegisterParameters(Parameter[] saved, FunctionPrototype observed) {
        if (observed.getNumParams() <= saved.length) return false;
        for (int i = 0; i < observed.getNumParams(); i++) {
            var param = observed.getParam(i);
            if (param == null || (i < saved.length ? !saved[i].getVariableStorage().equals(param.getStorage()) :
                !param.getStorage().isRegisterStorage())) return false;
        }
        return true;
    }

    record NativeSwitch(JsonArray labels, FunctionPrototype prototype) {}

    NativeSwitch verifyNative(Function function, Address jump, ArrayList<Address> targets, int timeout) {
        var decompiler = new DecompInterface();
        try {
            if (!decompiler.openProgram(currentProgram)) throw new IllegalStateException(decompiler.getLastMessage());
            var result = decompiler.decompileFunction(function, timeout, monitor);
            if (!result.decompileCompleted() || result.getHighFunction() == null)
                throw new IllegalStateException("Cannot verify recovered switch in native output");
            JumpTable[] tables = result.getHighFunction().getJumpTables();
            if (tables.length != 1 || !jump.equals(tables[0].getSwitchAddress()) ||
                !Arrays.equals(tables[0].getCases(), targets.toArray(Address[]::new)))
                throw new IllegalStateException("Native switch targets differ from the proved entries");
            Integer[] labels = tables[0].getLabelValues();
            if (labels == null || labels.length != targets.size())
                throw new IllegalStateException("Native switch labels are incomplete");
            JsonArray report = new JsonArray();
            for (int i = 0; i < labels.length; i++) {
                if (!Integer.valueOf(i).equals(labels[i]))
                    throw new IllegalStateException("Native switch labels differ from the proved indexes");
                report.add(labels[i]);
            }
            return new NativeSwitch(report, result.getHighFunction().getFunctionPrototype());
        } finally {
            decompiler.dispose();
        }
    }

    Address address(JsonObject row, String key) {
        return address(text(row, key));
    }

    Address address(String value) {
        if (!value.matches("0x[0-9a-f]{1,16}")) throw new IllegalArgumentException("Invalid switch address");
        return currentProgram.getAddressFactory().getDefaultAddressSpace()
            .getAddress(Long.parseUnsignedLong(value.substring(2), 16));
    }

    String text(JsonObject row, String key) {
        return row.get(key).getAsString();
    }
}
