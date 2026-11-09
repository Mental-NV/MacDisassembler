// Research query on a disposable copy of a previously captured owned Program.
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashSet;
import java.util.HexFormat;
import java.util.List;
import java.util.Set;

import com.google.gson.Gson;
import com.google.gson.JsonArray;
import com.google.gson.JsonElement;
import com.google.gson.JsonObject;
import com.google.gson.JsonParser;

import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileResults;
import ghidra.app.util.headless.HeadlessScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.FunctionDefinitionDataType;
import ghidra.program.model.data.ParameterDefinition;
import ghidra.program.model.data.ParameterDefinitionImpl;
import ghidra.program.model.data.Undefined8DataType;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.VariableStorage;
import ghidra.program.model.pcode.FunctionPrototype;
import ghidra.program.model.pcode.HighFunctionDBUtil;
import ghidra.program.model.pcode.Varnode;
import ghidra.program.model.symbol.Reference;
import ghidra.program.model.symbol.SourceType;

public class RecoverDispatchReturn extends HeadlessScript {
    static final String POLICY = "macscope-dispatch-return-recovery/1";

    record Recovery(Function root, Address call, FunctionPrototype prior, DataType resultType,
                    JsonArray targets, JsonObject report) {}

    @Override
    public void run() throws Exception {
        String[] args = getScriptArgs();
        if (args.length != 2 || isHeadlessAnalysisEnabled())
            throw new IllegalArgumentException("Expected a saved Program, request, and result path");
        Path request = Path.of(args[0]);
        if (Files.size(request) > 256 * 1024) throw new IllegalArgumentException("Oversized ABI request");
        JsonObject plan = JsonParser.parseString(Files.readString(request)).getAsJsonObject();
        if (!POLICY.equals(text(plan, "policy")) ||
            !text(plan, "image_sha256").equalsIgnoreCase(currentProgram.getExecutableSHA256()) ||
            !"x86:LE:64:default".equals(currentProgram.getLanguageID().getIdAsString()))
            throw new IllegalStateException("ABI request differs from the saved Program");

        JsonArray rows = plan.getAsJsonArray("requests");
        if (rows.isEmpty() || rows.size() > 32) throw new IllegalArgumentException("Unbounded ABI request");
        JsonArray results = new JsonArray();
        List<Recovery> pending = new ArrayList<>();
        Set<Address> roots = new HashSet<>();
        for (JsonElement element : rows) {
            monitor.checkCancelled();
            JsonObject row = element.getAsJsonObject();
            Function root = internal(text(row, "entry_va"));
            if (!roots.add(root.getEntryPoint())) throw new IllegalArgumentException("Duplicate ABI root");
            JsonObject decision = new JsonObject();
            Recovery recovery = prepare(root, row, decision);
            if (recovery != null) pending.add(recovery);
            results.add(decision);
        }
        for (Recovery recovery : pending) apply(recovery);
        JsonObject report = new JsonObject();
        report.addProperty("policy", POLICY);
        report.add("results", results);
        Files.writeString(Path.of(args[1]), new Gson().toJson(report),
            StandardOpenOption.CREATE_NEW, StandardOpenOption.WRITE);
    }

    Recovery prepare(Function root, JsonObject row, JsonObject report) throws Exception {
        Address call = address(text(row, "call_va"));
        checkBytes(row.getAsJsonArray("machine"), root, 128);
        JsonObject observer = row.getAsJsonObject("observer");
        Function caller = internal(text(observer, "entry_va"));
        checkBytes(observer.getAsJsonArray("sequence"), caller, 9);
        Instruction direct = currentProgram.getListing().getInstructionAt(address(text(observer, "call_va")));
        if (direct == null || !direct.getFlowType().isCall() || direct.getFlowType().isComputed() ||
            !Arrays.equals(direct.getFlows(), new Address[] {root.getEntryPoint()}))
            throw new IllegalStateException("Saved caller does not call the candidate");
        Instruction computed = currentProgram.getListing().getInstructionAt(call);
        if (computed == null || !root.getBody().contains(call) || !computed.getFlowType().isCall() ||
            !computed.getFlowType().isComputed() || computed.getFlows().length != 0)
            throw new IllegalStateException("Saved call site is not an unresolved computed call");
        for (Reference ref : currentProgram.getReferenceManager().getReferencesFrom(call))
            if (ref.getReferenceType().isCall())
                throw new IllegalStateException("Saved computed call has an existing call reference");

        report.addProperty("entry_va", text(row, "entry_va"));
        report.addProperty("call_va", text(row, "call_va"));
        FunctionPrototype before = prototype(root);
        report.addProperty("prior_return_storage", before.getReturnStorage().toString());
        SourceType signatureSource = root.getSignatureSource();
        if (signatureSource == SourceType.USER_DEFINED || signatureSource == SourceType.IMPORTED ||
            before.getReturnType().getLength() != 8 || !storage(before.getReturnStorage(), "RAX") ||
            before.isVarArg() || before.getNumParams() != 3)
            return skipped(report, "unsupported_or_already_typed_root");

        JsonArray targets = row.getAsJsonArray("target_vas");
        if (targets.isEmpty() || targets.size() > 32)
            throw new IllegalArgumentException("Unbounded ABI target set");
        DataType returnType = null;
        String convention = before.getModelName();
        Set<Address> entries = new HashSet<>();
        for (JsonElement target : targets) {
            Function callee = internal(target.getAsString());
            if (callee.equals(root) || !entries.add(callee.getEntryPoint()))
                throw new IllegalArgumentException("Invalid ABI target set");
            FunctionPrototype proto = prototype(callee);
            DataType type = proto.getReturnType();
            if (!convention.equals(proto.getModelName()) || proto.isVarArg() || proto.getNumParams() != 2 ||
                type.getLength() != 16 || !storage(proto.getReturnStorage(), "RDX", "RAX") ||
                !storage(proto.getParam(0).getStorage(), "RDI") ||
                !storage(proto.getParam(1).getStorage(), "RSI") ||
                returnType != null && !returnType.isEquivalent(type))
                return skipped(report, "callee_abi_disagreement");
            returnType = type;
        }
        return new Recovery(root, call, before, returnType, targets, report);
    }

    void apply(Recovery recovery) throws Exception {
        Function root = recovery.root();
        FunctionPrototype before = recovery.prior();
        String convention = before.getModelName();
        FunctionDefinitionDataType signature = new FunctionDefinitionDataType("dispatch_abi");
        signature.setCallingConvention(convention);
        signature.setReturnType(recovery.resultType());
        signature.setArguments(new ParameterDefinition[] {
            new ParameterDefinitionImpl("word_1", Undefined8DataType.dataType, null),
            new ParameterDefinitionImpl("word_2", Undefined8DataType.dataType, null)
        });
        HighFunctionDBUtil.writeOverride(root, recovery.call(), signature);
        root.setReturnType(recovery.resultType(), SourceType.ANALYSIS);

        FunctionPrototype after = prototype(root);
        if (!storage(after.getReturnStorage(), "RDX", "RAX") ||
            !recovery.resultType().isEquivalent(after.getReturnType()) ||
            !convention.equals(after.getModelName()) || before.getNumParams() != after.getNumParams())
            throw new IllegalStateException("The recovered root ABI disagrees with the verified request");
        for (int i = 0; i < before.getNumParams(); i++)
            if (!before.getParam(i).getStorage().equals(after.getParam(i).getStorage()) ||
                !before.getParam(i).getDataType().isEquivalent(after.getParam(i).getDataType()))
                throw new IllegalStateException("Dispatch ABI recovery changed an input parameter");

        recovery.report().addProperty("status", "applied");
        recovery.report().addProperty("return_storage", after.getReturnStorage().toString());
        recovery.report().addProperty("convention", convention);
        recovery.report().add("target_vas", recovery.targets());
    }

    FunctionPrototype prototype(Function function) {
        DecompInterface decompiler = new DecompInterface();
        try {
            decompiler.toggleSyntaxTree(true);
            if (!decompiler.openProgram(currentProgram))
                throw new IllegalStateException(decompiler.getLastMessage());
            DecompileResults result = decompiler.decompileFunction(function, 30, monitor);
            if (!result.decompileCompleted() || result.getHighFunction() == null)
                throw new IllegalStateException("Cannot verify ABI for " + function.getEntryPoint());
            return result.getHighFunction().getFunctionPrototype();
        } finally {
            decompiler.dispose();
        }
    }

    boolean storage(VariableStorage storage, String... names) {
        Varnode[] nodes = storage.getVarnodes();
        if (nodes.length != names.length) return false;
        for (int i = 0; i < names.length; i++) {
            if (!nodes[i].getAddress().equals(currentProgram.getRegister(names[i]).getAddress()) ||
                nodes[i].getSize() != 8) return false;
        }
        return true;
    }

    void checkBytes(JsonArray rows, Function function, int limit) throws Exception {
        if (rows.isEmpty() || rows.size() > limit) throw new IllegalArgumentException("Unbounded ABI byte evidence");
        Address next = null;
        for (JsonElement element : rows) {
            JsonObject row = element.getAsJsonObject();
            Address va = address(text(row, "va"));
            Instruction instruction = currentProgram.getListing().getInstructionAt(va);
            byte[] expected = HexFormat.of().parseHex(text(row, "bytes"));
            if (instruction == null || !function.getBody().contains(va) ||
                !Arrays.equals(instruction.getBytes(), expected) || next != null && !next.equals(va))
                throw new IllegalStateException("Saved ABI instruction disagrees with verified bytes");
            next = va.add(expected.length);
        }
    }

    Function internal(String va) {
        Function function = currentProgram.getFunctionManager().getFunctionAt(address(va));
        if (function == null || function.isExternal() || function.isThunk())
            throw new IllegalStateException("Expected a saved internal function entry");
        return function;
    }

    Address address(String va) {
        if (!va.matches("0x[0-9a-f]{1,16}")) throw new IllegalArgumentException("Invalid ABI address");
        long offset = Long.parseUnsignedLong(va.substring(2), 16);
        return currentProgram.getAddressFactory().getDefaultAddressSpace().getAddress(offset);
    }

    static String text(JsonObject value, String key) {
        return value.get(key).getAsString();
    }

    static Recovery skipped(JsonObject report, String reason) {
        report.addProperty("status", "skipped");
        report.addProperty("reason", reason);
        return null;
    }
}
