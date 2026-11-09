// Opt-in query on a disposable copy of a previously captured owned Program.
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashSet;
import java.util.HexFormat;
import java.util.List;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Set;

import com.google.gson.Gson;
import com.google.gson.JsonArray;
import com.google.gson.JsonElement;
import com.google.gson.JsonObject;
import com.google.gson.JsonParser;

import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileOptions;
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
import ghidra.program.model.pcode.HighFunction;
import ghidra.program.model.pcode.HighFunctionDBUtil;
import ghidra.program.model.pcode.Varnode;
import ghidra.program.model.symbol.Reference;
import ghidra.program.model.symbol.SourceType;

public class RecoverCallSignatures extends HeadlessScript {
    static final String DISPATCH = "macscope-dispatch-return-recovery/1";
    static final String DIRECT = "macscope-direct-call-signatures/1";
    int timeout;

    record Recovery(Function root, Address call, FunctionPrototype prior, DataType resultType,
                    JsonArray targets, JsonObject report) {}

    record DirectRecovery(Function parent, DataType resultType, String convention,
                          List<HighFunction> callees, JsonObject report) {}

    @Override
    public void run() throws Exception {
        String[] args = getScriptArgs();
        if (args.length != 3 || isHeadlessAnalysisEnabled())
            throw new IllegalArgumentException("Expected a saved Program, request, and result path");
        timeout = Integer.parseInt(args[2]);
        if (timeout < 1 || timeout > 300) throw new IllegalArgumentException("Invalid ABI query timeout");
        Path request = Path.of(args[0]);
        if (Files.size(request) > 256 * 1024) throw new IllegalArgumentException("Oversized ABI request");
        JsonObject plan = JsonParser.parseString(Files.readString(request)).getAsJsonObject();
        String policy = text(plan, "policy");
        if (!(DISPATCH.equals(policy) || DIRECT.equals(policy)) ||
            !text(plan, "image_sha256").equalsIgnoreCase(currentProgram.getExecutableSHA256()) ||
            !"x86:LE:64:default".equals(currentProgram.getLanguageID().getIdAsString()))
            throw new IllegalStateException("ABI request differs from the saved Program");

        JsonArray rows = plan.getAsJsonArray("requests");
        if (rows.isEmpty() || rows.size() > 32) throw new IllegalArgumentException("Unbounded ABI request");
        JsonObject report = new JsonObject();
        report.addProperty("policy", policy);
        if (DIRECT.equals(policy)) {
            String selected = text(plan, "entry_va");
            report.addProperty("entry_va", selected);
            report.add("results", recoverDirect(internal(selected), rows));
        } else {
            report.add("results", recoverDispatch(rows));
        }
        Files.writeString(Path.of(args[1]), new Gson().toJson(report),
            StandardOpenOption.CREATE_NEW, StandardOpenOption.WRITE);
    }

    JsonArray recoverDispatch(JsonArray rows) throws Exception {
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
        return results;
    }

    JsonArray recoverDirect(Function selected, JsonArray rows) throws Exception {
        JsonArray results = new JsonArray();
        List<DirectRecovery> pending = new ArrayList<>();
        Set<Address> parents = new HashSet<>();
        Map<Address, HighFunction> inferred = new LinkedHashMap<>();
        int sites = 0;
        for (JsonElement element : rows) {
            monitor.checkCancelled();
            JsonObject row = element.getAsJsonObject();
            Function parent = internal(text(row, "parent_va"));
            if (!parents.add(parent.getEntryPoint())) throw new IllegalArgumentException("Duplicate direct parent");
            JsonArray calls = row.getAsJsonArray("calls");
            sites += calls.size();
            if (calls.isEmpty() || sites > 16) throw new IllegalArgumentException("Unbounded direct call sites");
            verifyPath(selected, parent, row.getAsJsonArray("path"));
            verifyObserver(parent, row.getAsJsonObject("observer"));
            JsonObject decision = new JsonObject();
            decision.addProperty("parent_va", text(row, "parent_va"));
            JsonArray recorded = new JsonArray();
            List<Function> targets = new ArrayList<>();
            Set<Address> addresses = new HashSet<>();
            for (JsonElement callElement : calls) {
                JsonObject site = callElement.getAsJsonObject();
                Function target = internal(text(site, "target_va"));
                if (!text(site, "owner_va").equals(text(row, "parent_va")) ||
                    !addresses.add(address(text(site, "call_va"))) || target.equals(parent))
                    throw new IllegalArgumentException("Invalid direct call site");
                checkBytes(site.getAsJsonArray("sequence"), parent, 3);
                checkDirect(parent, address(text(site, "call_va")), target);
                targets.add(target);
                JsonObject item = new JsonObject();
                item.add("call_va", site.get("call_va"));
                item.add("target_va", site.get("target_va"));
                recorded.add(item);
            }
            decision.add("sites", recorded);
            results.add(decision);
            List<HighFunction> callees = new ArrayList<>();
            DataType shared = null;
            String convention = null;
            for (Function target : targets) {
                if (target.getSignatureSource() == SourceType.USER_DEFINED ||
                    target.getSignatureSource() == SourceType.IMPORTED) {
                    skipped(decision, "protected_callee_signature");
                    break;
                }
                HighFunction high = inferred.computeIfAbsent(target.getEntryPoint(), key -> highFunction(target));
                FunctionPrototype proto = high.getFunctionPrototype();
                if (!twoWordCallee(proto) || shared != null && (!shared.isEquivalent(proto.getReturnType()) ||
                    !convention.equals(proto.getModelName()))) {
                    skipped(decision, "unsupported_callee_signature");
                    break;
                }
                shared = proto.getReturnType();
                convention = proto.getModelName();
                callees.add(high);
            }
            if (callees.size() == targets.size()) {
                pending.add(new DirectRecovery(parent, shared, convention, callees, decision));
            }
        }
        Set<Address> committed = new HashSet<>();
        for (DirectRecovery recovery : pending) {
            for (HighFunction callee : recovery.callees()) {
                if (committed.add(callee.getFunction().getEntryPoint())) {
                    HighFunctionDBUtil.commitParamsToDatabase(callee, true,
                        HighFunctionDBUtil.ReturnCommitOption.COMMIT, SourceType.ANALYSIS);
                    verifyCommitted(callee);
                }
            }
        }
        for (DirectRecovery recovery : pending) {
            FunctionPrototype after = prototype(recovery.parent());
            if (!storage(after.getReturnStorage(), "RDX", "RAX") || after.isVarArg() ||
                !recovery.resultType().isEquivalent(after.getReturnType()) ||
                !recovery.convention().equals(after.getModelName()))
                throw new IllegalStateException("The forwarding parent disagrees with the verified callee ABI");
            recovery.report().addProperty("status", "applied");
            recovery.report().addProperty("return_storage", after.getReturnStorage().toString());
        }
        return results;
    }

    boolean twoWordCallee(FunctionPrototype proto) {
        return !proto.isVarArg() && proto.getNumParams() == 2 && proto.getReturnType().getLength() == 16 &&
            storage(proto.getReturnStorage(), "RDX", "RAX") &&
            proto.getParam(0) != null && proto.getParam(1) != null &&
            storage(proto.getParam(0).getStorage(), "RDI") && storage(proto.getParam(1).getStorage(), "RSI");
    }

    void verifyCommitted(HighFunction high) {
        Function function = high.getFunction();
        FunctionPrototype proto = high.getFunctionPrototype();
        if (function.getParameterCount() != 2 ||
            !function.getReturnType().isEquivalent(proto.getReturnType()) ||
            !storage(function.getReturn().getVariableStorage(), "RDX", "RAX") ||
            !storage(function.getParameter(0).getVariableStorage(), "RDI") ||
            !storage(function.getParameter(1).getVariableStorage(), "RSI"))
            throw new IllegalStateException("The committed callee ABI differs from the inferred signature");
    }

    void verifyPath(Function selected, Function parent, JsonArray path) throws Exception {
        if (path.size() > 2) throw new IllegalArgumentException("Unbounded direct call path");
        Function owner = selected;
        for (JsonElement element : path) {
            JsonObject edge = element.getAsJsonObject();
            if (!owner.getEntryPoint().equals(address(text(edge, "owner_va"))))
                throw new IllegalStateException("Direct call path does not belong to the selected function");
            Function target = internal(text(edge, "target_va"));
            Address site = address(text(edge, "call_va"));
            Instruction instruction = checkDirect(owner, site, target);
            if (!Arrays.equals(instruction.getBytes(), HexFormat.of().parseHex(text(edge, "bytes"))))
                throw new IllegalStateException("Saved direct call differs from the proof");
            owner = target;
        }
        if (!owner.equals(parent)) throw new IllegalStateException("Direct call path did not reach its parent");
    }

    Instruction checkDirect(Function owner, Address site, Function target) {
        Instruction call = currentProgram.getListing().getInstructionAt(site);
        if (call == null || !owner.getBody().contains(site) || !call.getFlowType().isCall() ||
            call.getFlowType().isComputed() || !Arrays.equals(call.getFlows(), new Address[] {target.getEntryPoint()}))
            throw new IllegalStateException("Saved caller does not call the proved target");
        return call;
    }

    void verifyObserver(Function parent, JsonObject observer) throws Exception {
        Function caller = internal(text(observer, "entry_va"));
        checkBytes(observer.getAsJsonArray("sequence"), caller, 9);
        checkDirect(caller, address(text(observer, "call_va")), parent);
    }

    Recovery prepare(Function root, JsonObject row, JsonObject report) throws Exception {
        Address call = address(text(row, "call_va"));
        checkBytes(row.getAsJsonArray("machine"), root, 128);
        verifyObserver(root, row.getAsJsonObject("observer"));
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
        return highFunction(function).getFunctionPrototype();
    }

    HighFunction highFunction(Function function) {
        DecompInterface decompiler = new DecompInterface();
        try {
            DecompileOptions options = new DecompileOptions();
            options.setDefaultTimeout(timeout);
            options.setMaxInstructions(100000);
            options.setMaxJumpTableEntries(4096);
            options.setMaxPayloadMBytes(8);
            decompiler.setOptions(options);
            decompiler.toggleSyntaxTree(true);
            if (!decompiler.openProgram(currentProgram))
                throw new IllegalStateException(decompiler.getLastMessage());
            DecompileResults result = decompiler.decompileFunction(function, timeout, monitor);
            if (!result.decompileCompleted() || result.getHighFunction() == null)
                throw new IllegalStateException("Cannot verify ABI for " + function.getEntryPoint());
            return result.getHighFunction();
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
