// NON-SHIPPING owned experiment. No ordinary query receipt is produced.
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;
import java.security.MessageDigest;
import java.util.HexFormat;
import java.util.Set;
import com.google.gson.Gson;
import com.google.gson.JsonArray;
import com.google.gson.JsonObject;
import com.google.gson.JsonParser;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.listing.Function;
import ghidra.program.model.pcode.HighFunction;

public class OwnedScopedParameters extends RecoverCallSignatures {
    static final String EXPERIMENT = "macscope-owned-focused-parameters/1";
    JsonObject trial;
    JsonArray bodies = new JsonArray(), checks = new JsonArray();
    String phase = "before_commit";

    @Override public void run() throws Exception {
        String[] args = getScriptArgs();
        if (args.length != 3 || isHeadlessAnalysisEnabled() || !"12.2".equals(getGhidraVersion()))
            throw new IllegalStateException("Owned no-analysis experiment required");
        Path input = Path.of(args[0]);
        if (Files.size(input) > 256 * 1024) throw new IllegalStateException("Request limit");
        trial = JsonParser.parseString(Files.readString(input)).getAsJsonObject();
        if (!trial.keySet().equals(Set.of("policy","image_sha256","arch","entry_va","requests","experiment","arm","caller","callee")) ||
            !EXPERIMENT.equals(text(trial,"experiment")) || !PARAMETERS.equals(text(trial,"policy")) ||
            !"arm64".equals(text(trial,"arch")) ||
            !text(trial,"image_sha256").equals(currentProgram.getExecutableSHA256()))
            throw new IllegalStateException("Experiment identity differs");
        String arm = text(trial,"arm");
        if (!Set.of("caller","prepared","inferred").contains(arm)) throw new IllegalStateException("Arm");
        JsonObject caller = trial.getAsJsonObject("caller"), callee = trial.getAsJsonObject("callee");
        if (!text(caller,"entry_va").equals(text(trial,"entry_va")) ||
            trial.getAsJsonArray("requests").size() != 1) throw new IllegalStateException("Selection");
        JsonObject selected = trial.getAsJsonArray("requests").get(0).getAsJsonObject();
        if (!text(selected,"target_va").equals(text(callee,"entry_va")) ||
            selected.getAsJsonArray("path").size() != 1) throw new IllegalStateException("Direct edge only");
        long cs = value(caller,"entry_va"), ce = value(caller,"end_va_exclusive");
        long ds = value(callee,"entry_va"), de = value(callee,"end_va_exclusive");
        if (cs < de && ds < ce || ce-cs+de-ds > 16384) throw new IllegalStateException("Overlapping/large selection");
        for (JsonObject p : new JsonObject[]{caller, callee}) {
            long lo=value(p,"entry_va"), hi=value(p,"end_va_exclusive");
            if(lo%4!=0 || hi%4!=0 || hi<=lo || hi-lo>8192 || p.get("length").getAsLong()!=hi-lo)
                throw new IllegalStateException("Pinned extent invalid");
        }
        Function root = internal(text(caller,"entry_va"));
        checkBody(root, caller, false);
        JsonObject edge = selected.getAsJsonArray("path").get(0).getAsJsonObject();
        Address site = address(text(edge,"call_va"));
        var insn = currentProgram.getListing().getInstructionAt(site);
        if (!text(edge,"owner_va").equals(text(caller,"entry_va")) ||
            !text(edge,"target_va").equals(text(callee,"entry_va")) ||
            !root.getBody().contains(site) || insn == null || !insn.getFlowType().isCall() ||
            insn.getFlowType().isComputed() || insn.getFlows().length != 1 ||
            !insn.getFlows()[0].equals(address(text(callee,"entry_va"))) ||
            !HexFormat.of().formatHex(insn.getBytes()).equals(text(edge,"bytes")))
            throw new IllegalStateException("Unverified direct edge");
        if (!arm.equals("caller")) checkBody(internal(text(callee,"entry_va")), callee, true);
        if (arm.equals("inferred")) super.run();
        JsonObject out = new JsonObject();
        out.addProperty("schema", EXPERIMENT); out.addProperty("arm", arm);
        out.add("body_checks", bodies); out.add("native_checks", checks);
        Files.writeString(Path.of(args[1]+".guards.json"),new Gson().toJson(out),
            StandardOpenOption.CREATE_NEW,StandardOpenOption.WRITE);
    }

    long value(JsonObject p, String key) {
        long v = Long.parseUnsignedLong(text(p,key).substring(2),16);
        if (v < 0) throw new IllegalStateException("Experiment supports low-half addresses only");
        return v;
    }

    void checkBody(Function f, JsonObject proof, boolean leaf) throws Exception {
        long a=value(proof,"entry_va"), b=value(proof,"end_va_exclusive");
        if (a%4!=0 || b%4!=0 || b<=a || b-a>8192 || proof.get("length").getAsLong()!=b-a)
            throw new IllegalStateException("Extent limit");
        Address start=address(text(proof,"entry_va")), end=address(text(proof,"end_va_exclusive")).subtract(1);
        if (!f.getEntryPoint().equals(start) || !new AddressSet(start,end).hasSameAddresses(f.getBody()))
            throw new IllegalStateException("Prepared body differs from independently pinned extent");
        byte[] bytes=new byte[(int)(b-a)];
        if (currentProgram.getMemory().getBytes(start,bytes)!=bytes.length ||
            !HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(bytes)).equals(text(proof,"extent_sha256")))
            throw new IllegalStateException("Changed body bytes");
        var it=currentProgram.getListing().getInstructions(f.getBody(),true); long next=a;
        while(it.hasNext()) {
            monitor.checkCancelled(); var i=it.next();
            if(i.getAddress().getOffset()!=next || i.getLength()!=4) throw new IllegalStateException("Noncontiguous instructions");
            next+=4;
            if(leaf) {
                boolean ret=HexFormat.of().formatHex(i.getBytes()).equals("c0035fd6");
                var flow=i.getFlowType();
                if(flow.isCall() || flow.isComputed()&&!ret || flow.isTerminal()&&!ret)
                    throw new IllegalStateException("Unsupported callee flow");
                for(Address target:i.getFlows()) if(!f.getBody().contains(target)) throw new IllegalStateException("Callee branch escapes");
                if(i.getFallThrough()!=null&&!f.getBody().contains(i.getFallThrough())) throw new IllegalStateException("Callee fallthrough escapes");
            }
        }
        if(next!=b) throw new IllegalStateException("Incomplete body");
        JsonObject check=new JsonObject(); check.addProperty("entry_va",text(proof,"entry_va"));
        check.addProperty("extent_sha256",text(proof,"extent_sha256"));check.addProperty("leaf",leaf);bodies.add(check);
    }

    void checkNative(HighFunction high) throws Exception {
        JsonObject p=trial.getAsJsonObject("callee");
        if(high==null || !high.getFunction().getEntryPoint().equals(address(text(p,"entry_va"))))
            throw new IllegalStateException("Unexpected HighFunction");
        checkBody(high.getFunction(),p,true);
        AddressSet pinned=new AddressSet(address(text(p,"entry_va")),address(text(p,"end_va_exclusive")).subtract(1));
        var ops=high.getPcodeOps(); int count=0;
        while(ops.hasNext()) {
            monitor.checkCancelled(); if(++count>100000) throw new IllegalStateException("Native scope truncated");
            Address target=ops.next().getSeqnum().getTarget();
            if(target==null || !target.isMemoryAddress() || !pinned.contains(target))
                throw new IllegalStateException("Native operation outside independently pinned extent");
        }
        if(count==0) throw new IllegalStateException("Native scope unavailable");
        JsonObject check=new JsonObject();check.addProperty("entry_va",text(p,"entry_va"));
        check.addProperty("extent_sha256",text(p,"extent_sha256"));check.addProperty("operations_scanned",count);
        check.addProperty("phase",phase);check.addProperty("status","complete");checks.add(check);
    }

    @Override HighFunction highFunction(Function function) {
        HighFunction high=super.highFunction(function);
        try {checkNative(high);} catch(Exception e) {throw new IllegalStateException("Scoped inference refused",e);}
        return high;
    }

    @Override void commitVerifiedParameters(HighFunction high,int count) throws Exception {
        checkNative(high);super.commitVerifiedParameters(high,count);
        phase="after_commit";
        try {
            HighFunction after=highFunction(high.getFunction());
            if(!registerParameters(high.getFunctionPrototype(),inputRegisters("arm64")).equals(
                registerParameters(after.getFunctionPrototype(),inputRegisters("arm64"))))
                throw new IllegalStateException("Post-commit inferred inputs changed");
        } finally {phase="before_commit";}
    }
}
