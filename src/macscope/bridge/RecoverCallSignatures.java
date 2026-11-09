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
import ghidra.program.model.data.AbstractIntegerDataType;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.FunctionDefinitionDataType;
import ghidra.program.model.data.IntegerDataType;
import ghidra.program.model.data.ParameterDefinition;
import ghidra.program.model.data.ParameterDefinitionImpl;
import ghidra.program.model.data.Undefined;
import ghidra.program.model.data.Undefined8DataType;
import ghidra.program.model.data.VoidDataType;
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
    static final String SCALAR = "macscope-scalar-call-signatures/1";
    static final String PARAMETERS = "macscope-callee-parameters/1";
    static final String FORWARDED = "macscope-forwarded-return/1";
    static final String X86 = "x86:LE:64:default", ARM = "AARCH64:LE:64:AppleSilicon";
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
        String language = currentProgram.getLanguageID().getIdAsString();
        boolean supported = switch (policy) {
            case DISPATCH, DIRECT -> X86.equals(language);
            case SCALAR, PARAMETERS, FORWARDED -> X86.equals(language) || ARM.equals(language);
            default -> false;
        };
        if (!supported || !text(plan, "image_sha256").equalsIgnoreCase(currentProgram.getExecutableSHA256()))
            throw new IllegalStateException("ABI request differs from the saved Program");

        JsonArray rows = plan.getAsJsonArray("requests");
        if (rows.isEmpty() || rows.size() > 32) throw new IllegalArgumentException("Unbounded ABI request");
        JsonObject report = new JsonObject();
        report.addProperty("policy", policy);
        if (PARAMETERS.equals(policy) || FORWARDED.equals(policy)) {
            String selected = text(plan, "entry_va");
            String expectedArch = ARM.equals(language) ? "arm64" : "x86_64";
            if (!expectedArch.equals(text(plan, "arch")))
                throw new IllegalStateException("Parameter proof architecture differs from the Program");
            report.addProperty("entry_va", selected);
            Function root = internal(selected);
            report.add("results", PARAMETERS.equals(policy)
                ? recoverParameters(root, rows, expectedArch) : recoverForwarded(root, rows, expectedArch));
        } else if (SCALAR.equals(policy)) {
            String selected = text(plan, "entry_va");
            report.addProperty("entry_va", selected);
            report.add("results", recoverScalar(internal(selected), rows, language));
        } else if (DIRECT.equals(policy)) {
            String selected = text(plan, "entry_va");
            report.addProperty("entry_va", selected);
            report.add("results", recoverDirect(internal(selected), rows));
        } else {
            report.add("results", recoverDispatch(rows));
        }
        Files.writeString(Path.of(args[1]), new Gson().toJson(report),
            StandardOpenOption.CREATE_NEW, StandardOpenOption.WRITE);
    }

    JsonArray recoverParameters(Function selected, JsonArray rows, String arch) throws Exception {
        if (rows.size() > 16) throw new IllegalArgumentException("Unbounded callee parameter query");
        String[] slots = inputRegisters(arch);
        Map<Function, JsonObject> targets = new LinkedHashMap<>();
        for (JsonElement element : rows) {
            JsonObject row = element.getAsJsonObject();
            String entry = text(row, "target_va");
            Function callee = internal(entry);
            JsonObject result = new JsonObject();
            result.addProperty("target_va", entry);
            if (callee.equals(selected) || targets.putIfAbsent(callee, result) != null)
                throw new IllegalArgumentException("Invalid callee parameter target");
            verifyPath(selected, callee, row.getAsJsonArray("path"));
        }
        JsonArray results = new JsonArray();
        for (var item : targets.entrySet()) {
            monitor.checkCancelled();
            Function callee = item.getKey();
            JsonObject result = item.getValue();
            results.add(result);
            if (callee.getSignatureSource() != SourceType.DEFAULT) {
                skipped(result, "existing_callee_parameters");
                continue;
            }
            if (callee.hasCustomVariableStorage()) {
                skipped(result, "unsupported_callee_parameters");
                continue;
            }
            HighFunction high = highFunction(callee);
            FunctionPrototype inferred = high.getFunctionPrototype();
            JsonArray parameters = registerParameters(inferred, slots);
            if (parameters == null) {
                skipped(result, "unsupported_callee_parameters");
                continue;
            }
            commitVerifiedParameters(high, parameters.size());
            result.addProperty("status", "applied");
            result.addProperty("return_unchanged", true);
            result.add("parameters", parameters);
        }
        return results;
    }

    String[] inputRegisters(String arch) {
        return arch.equals("arm64")
            ? new String[] {"x0", "x1", "x2", "x3", "x4", "x5", "x6", "x7"}
            : new String[] {"RDI", "RSI", "RDX", "RCX", "R8", "R9"};
    }

    void commitVerifiedParameters(HighFunction high, int count) throws Exception {
        Function callee = high.getFunction();
        FunctionPrototype inferred = high.getFunctionPrototype();
        DataType oldReturn = callee.getReturnType();
        VariableStorage oldStorage = callee.getReturn().getVariableStorage();
        HighFunctionDBUtil.commitParamsToDatabase(high, true,
            HighFunctionDBUtil.ReturnCommitOption.NO_COMMIT, SourceType.ANALYSIS);
        if (!oldReturn.isEquivalent(callee.getReturnType()) ||
            !oldStorage.equals(callee.getReturn().getVariableStorage()) ||
            callee.getParameterCount() != count)
            throw new IllegalStateException("Callee parameter recovery changed the return or parameter count");
        for (int i = 0; i < count; i++) {
            var actual = callee.getParameter(i);
            var observed = inferred.getParam(i);
            if (!actual.getDataType().isEquivalent(observed.getDataType()) ||
                !actual.getVariableStorage().equals(observed.getStorage()))
                throw new IllegalStateException("Committed callee parameter differs from native inference");
        }
    }

    boolean ordinaryInputs(FunctionPrototype proto, String[] slots) {
        return !proto.isVarArg() && (proto.getNumParams() == 0 || registerParameters(proto, slots) != null);
    }

    boolean protectsReturn(Function function) {
        return function.getSignatureSource() == SourceType.USER_DEFINED ||
            function.getSignatureSource() == SourceType.IMPORTED;
    }

    JsonArray recoverForwarded(Function root, JsonArray rows, String arch) throws Exception {
        if (rows.size() != 1) throw new IllegalArgumentException("Expected one forwarded return");
        JsonObject proof = rows.get(0).getAsJsonObject(), result = new JsonObject();
        JsonArray results = new JsonArray();
        results.add(result);
        for (String key : List.of("target_va", "call_va", "observer_va", "observer_call_va",
                                  "store_va", "destination_va"))
            result.add(key, proof.get(key));

        Function callee = internal(text(proof, "target_va"));
        Function observer = internal(text(proof, "observer_va"));
        Address call = address(text(proof, "call_va")), observedCall = address(text(proof, "observer_call_va"));
        JsonArray tail = proof.getAsJsonArray("tail"), reads = proof.getAsJsonArray("observer");
        checkBytes(tail, root, 4);
        checkBytes(reads, observer, 8);
        if (root.equals(callee) || observer.equals(root) || observer.equals(callee) ||
            !address(text(tail.get(0).getAsJsonObject(), "va")).equals(call) ||
            !address(text(reads.get(0).getAsJsonObject(), "va")).equals(observedCall) ||
            !text(reads.get(reads.size() - 1).getAsJsonObject(), "va").equals(text(proof, "store_va")))
            throw new IllegalStateException("Unexpected forwarded return path");
        checkDirect(root, call, callee);
        checkDirect(observer, observedCall, root);
        Address last = address(text(tail.get(tail.size() - 1).getAsJsonObject(), "va"));
        if (!verifiedForwardingFlow(root, call, last)) {
            skipped(result, "unverified_forwarding_flow");
            return results;
        }
        if (protectsReturn(root) || protectsReturn(callee) || !Undefined.isUndefined(root.getReturnType())) {
            skipped(result, "existing_forwarded_return");
            return results;
        }

        String register = arch.equals("arm64") ? "x0" : "RAX";
        String[] slots = inputRegisters(arch);
        FunctionPrototype leaf = prototype(callee);
        DataType type = leaf.getReturnType();
        if (root.hasCustomVariableStorage() || callee.hasCustomVariableStorage() ||
            root.hasNoReturn() || callee.hasNoReturn() ||
            !(type instanceof AbstractIntegerDataType) || type.getLength() != 8 ||
            !registerStorage(leaf.getReturnStorage(), register, 8) ||
            !ordinaryInputs(leaf, slots) || !ordinaryInputs(prototype(root), slots) ||
            !Undefined.isUndefined(callee.getReturnType()) && !type.isEquivalent(callee.getReturnType())) {
            skipped(result, "unsupported_forwarded_signature");
            return results;
        }

        recoverParameters(root, proof.getAsJsonArray("parameters"), arch);
        HighFunction recoveredLeaf = highFunction(callee);
        FunctionPrototype afterLeaf = recoveredLeaf.getFunctionPrototype();
        if (!type.isEquivalent(afterLeaf.getReturnType()) || !registerStorage(afterLeaf.getReturnStorage(), register, 8) ||
            !ordinaryInputs(afterLeaf, slots))
            throw new IllegalStateException("Callee parameters changed the inferred forwarded return");
        if (callee.getSignatureSource() == SourceType.DEFAULT)
            commitVerifiedParameters(recoveredLeaf, afterLeaf.getNumParams());
        applyWordReturn(callee, type, register);

        HighFunction wrapper = highFunction(root);
        FunctionPrototype wrapperProto = wrapper.getFunctionPrototype();
        if (!ordinaryInputs(wrapperProto, slots))
            throw new IllegalStateException("Unexpected wrapper parameters after callee inference");
        if (root.getSignatureSource() == SourceType.DEFAULT)
            commitVerifiedParameters(wrapper, wrapperProto.getNumParams());
        applyWordReturn(root, type, register);
        FunctionPrototype after = prototype(root);
        if (!type.isEquivalent(after.getReturnType()) || !registerStorage(after.getReturnStorage(), register, 8))
            throw new IllegalStateException("Decompiler did not retain the proved return");
        result.addProperty("status", "applied");
        result.addProperty("return_storage", register + ":8");
        return results;
    }

    boolean verifiedForwardingFlow(Function root, Address call, Address last) {
        if (!root.getBody().getMaxAddress().equals(last.add(currentProgram.getListing().getInstructionAt(last)
                .getLength() - 1))) return false;
        var instructions = currentProgram.getListing().getInstructions(root.getBody(), true);
        while (instructions.hasNext()) {
            Instruction instruction = instructions.next();
            Address address = instruction.getAddress();
            var flow = instruction.getFlowType();
            if (address.equals(last) ? !flow.isTerminal() : flow.isTerminal() || flow.isComputed())
                return false;
            if (flow.isJump()) {
                for (Address target : instruction.getFlows()) {
                    if (!root.getBody().contains(target) || target.compareTo(call) > 0) return false;
                }
                if (instruction.getFlows().length == 0) return false;
            }
        }
        return true;
    }

    void applyWordReturn(Function function, DataType type, String register) throws Exception {
        var before = function.getParameters();
        if (Undefined.isUndefined(function.getReturnType()))
            function.setReturnType(type, SourceType.ANALYSIS);
        var after = function.getParameters();
        if (!type.isEquivalent(function.getReturnType()) ||
            !registerStorage(function.getReturn().getVariableStorage(), register, 8) || before.length != after.length)
            throw new IllegalStateException("Committed forwarded return does not match the proved ABI");
        for (int i = 0; i < before.length; i++) {
            if (!before[i].getDataType().isEquivalent(after[i].getDataType()) ||
                !before[i].getVariableStorage().equals(after[i].getVariableStorage()))
                throw new IllegalStateException("Forwarded return changed an input parameter");
        }
    }

    JsonArray registerParameters(FunctionPrototype proto, String[] slots) {
        int count = proto.getNumParams();
        if (proto.isVarArg() || count < 1 || count > slots.length) return null;
        JsonArray result = new JsonArray();
        for (int i = 0; i < count; i++) {
            var parameter = proto.getParam(i);
            if (parameter == null) return null;
            int size = parameter.getDataType().getLength();
            if (!Set.of(1, 2, 4, 8).contains(size) ||
                !registerStorage(parameter.getStorage(), slots[i], size)) return null;
            JsonObject row = new JsonObject();
            row.addProperty("register", slots[i]);
            row.addProperty("size", size);
            result.add(row);
        }
        return result;
    }

    JsonArray recoverScalar(Function selected, JsonArray rows, String language) throws Exception {
        if (rows.size() > 16) throw new IllegalArgumentException("Unbounded scalar call sites");
        JsonArray results = new JsonArray();
        Map<Address, String> changed = new LinkedHashMap<>();
        for (JsonElement element : rows) {
            monitor.checkCancelled();
            JsonObject row = element.getAsJsonObject();
            Function caller = internal(text(row, "caller_va"));
            Address site = address(text(row, "call_va"));
            Address target = address(text(row, "target_va"));
            JsonObject decision = new JsonObject();
            for (String key : List.of("kind", "caller_va", "call_va", "target_va")) {
                decision.add(key, row.get(key));
            }
            results.add(decision);
            JsonArray witness = row.getAsJsonArray("caller");
            if (!address(text(witness.get(0).getAsJsonObject(), "va")).equals(site))
                throw new IllegalStateException("Scalar witness does not start at the call");
            checkBytes(witness, caller, 2);
            if (X86.equals(language) && "zero_extended_eax".equals(text(row, "kind"))) {
                Function callee = internal(text(row, "target_va"));
                if (!selected.equals(caller) && !selected.equals(callee))
                    throw new IllegalStateException("Scalar witness does not involve the selected function");
                checkDirect(caller, site, callee);
                if (witness.size() != 2 || !Set.of("83f800", "85c0")
                    .contains(text(witness.get(1).getAsJsonObject(), "bytes")))
                    throw new IllegalStateException("Scalar caller does not test the whole return register");
                verifyZeroExtendedLeaf(callee, row.getAsJsonArray("leaf"));
                String reason = widenResult(callee);
                if (reason != null) {
                    skipped(decision, reason);
                    continue;
                }
                decision.addProperty("return_storage", "EAX:4");
            } else if (ARM.equals(language) && "darwin_stack_failure".equals(text(row, "kind"))) {
                Function thunk = getFunctionAt(target);
                if (!selected.equals(caller) || witness.size() != 1 || thunk == null || !thunk.isThunk())
                    throw new IllegalStateException("Invalid Darwin stack failure thunk");
                checkDirect(caller, site, thunk);
                checkBytes(row.getAsJsonArray("stub"), thunk, 3);
                Function imported = thunk.getThunkedFunction(true);
                if (imported == null || !imported.isExternal() || !imported.getName().equals("___stack_chk_fail") ||
                    !imported.hasNoReturn() || imported.hasVarArgs() || imported.getParameterCount() != 0) {
                    skipped(decision, "unsupported_callee_signature");
                    continue;
                }
                if (imported.getSignatureSource() == SourceType.USER_DEFINED) {
                    skipped(decision, "protected_callee_signature");
                    continue;
                }
                String bind = text(row, "bind_va");
                String priorBind = changed.putIfAbsent(target, bind);
                if (priorBind != null && !priorBind.equals(bind))
                    throw new IllegalStateException("Conflicting bindings for the same stack failure thunk");
                if (priorBind == null) {
                    imported.setReturnType(VoidDataType.dataType, SourceType.IMPORTED);
                    imported.setSignatureSource(SourceType.IMPORTED);
                }
                if (!imported.getReturnType().isEquivalent(VoidDataType.dataType) ||
                    imported.getParameterCount() != 0 || !imported.hasNoReturn())
                    throw new IllegalStateException("Stack failure import ABI differs after applying the prototype");
                decision.addProperty("bind_va", bind);
                decision.addProperty("prototype", "void (void)");
                decision.addProperty("noreturn", true);
            } else {
                throw new IllegalStateException("Scalar witness does not match the Program architecture");
            }
            decision.addProperty("status", "applied");
        }
        return results;
    }

    void verifyZeroExtendedLeaf(Function callee, JsonArray leaf) throws Exception {
        checkBytes(leaf, callee, 1024);
        int count = leaf.size();
        JsonObject end = leaf.get(count - 1).getAsJsonObject();
        Address exit = address(text(end, "va"));
        int extend = count - 2;
        if (extend > 0 && "5d".equals(text(leaf.get(extend).getAsJsonObject(), "bytes"))) extend--;
        if (extend < 0 || !"c3".equals(text(end, "bytes")) ||
            !"0fb6c0".equals(text(leaf.get(extend).getAsJsonObject(), "bytes")) ||
            !callee.getEntryPoint().equals(address(text(leaf.get(0).getAsJsonObject(), "va"))) ||
            callee.getBody().getNumAddresses() != exit.subtract(callee.getEntryPoint()) + 1)
            throw new IllegalStateException("Scalar proof does not cover the complete leaf and its return");
        Address lastDefinition = address(text(leaf.get(extend).getAsJsonObject(), "va"));
        var instructions = currentProgram.getListing().getInstructions(callee.getBody(), true);
        while (instructions.hasNext()) {
            Instruction instruction = instructions.next();
            var flow = instruction.getFlowType();
            Address location = instruction.getAddress();
            if (location.equals(exit) ? !flow.isTerminal() :
                flow.isCall() || flow.isComputed() || flow.isTerminal() ||
                !flow.isJump() && instruction.getFallThrough() == null)
                throw new IllegalStateException("Unexpected scalar leaf transfer");
            for (Address branch : instruction.getFlows()) {
                if (!callee.getBody().contains(branch) || branch.compareTo(lastDefinition) > 0)
                    throw new IllegalStateException("A branch bypasses the full return definition");
            }
        }
    }

    String widenResult(Function callee) throws Exception {
        SourceType source = callee.getSignatureSource();
        if (source == SourceType.USER_DEFINED || source == SourceType.IMPORTED)
            return "protected_callee_signature";
        if (callee.hasCustomVariableStorage() || callee.hasNoReturn())
            return "unsupported_callee_signature";
        HighFunction high = highFunction(callee);
        FunctionPrototype prior = high.getFunctionPrototype();
        if (prior.isVarArg() || prior.getReturnType().getLength() != 1 ||
            !registerStorage(prior.getReturnStorage(), "AL", 1))
            return "unsupported_callee_signature";
        if (source == SourceType.DEFAULT) {
            HighFunctionDBUtil.commitParamsToDatabase(high, true,
                HighFunctionDBUtil.ReturnCommitOption.NO_COMMIT, SourceType.ANALYSIS);
        }
        var inputs = callee.getParameters();
        callee.setReturnType(IntegerDataType.dataType, SourceType.ANALYSIS);
        callee.setSignatureSource(SourceType.ANALYSIS);
        var after = callee.getParameters();
        if (!registerStorage(callee.getReturn().getVariableStorage(), "EAX", 4) || inputs.length != after.length)
            throw new IllegalStateException("Scalar signature did not widen the saved return register");
        for (int i = 0; i < after.length; i++) {
            if (!inputs[i].getDataType().isEquivalent(after[i].getDataType()) ||
                !inputs[i].getVariableStorage().equals(after[i].getVariableStorage()))
                throw new IllegalStateException("Scalar signature changed an input");
        }
        return null;
    }

    boolean registerStorage(VariableStorage storage, String register, int size) {
        Varnode[] nodes = storage.getVarnodes();
        return nodes.length == 1 && nodes[0].getSize() == size &&
            nodes[0].getAddress().equals(currentProgram.getRegister(register).getAddress());
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
