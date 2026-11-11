// NON-SHIPPING owned injected negatives. Never export the synthetic HighFunction.
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;
import java.security.MessageDigest;
import java.util.ArrayList;
import java.util.HexFormat;
import java.util.Set;
import java.util.TreeSet;
import com.google.gson.Gson;
import com.google.gson.JsonObject;
import com.google.gson.JsonParser;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.Variable;
import ghidra.program.model.pcode.HighFunction;
import ghidra.program.model.pcode.PcodeOp;
import ghidra.program.model.pcode.SequenceNumber;
import ghidra.program.model.pcode.Varnode;

public class OwnedNativeControls extends OwnedScopedParameters {
    static final String CONTROL="macscope-owned-native-controls/1";
    static final String OWNED="53345f8f9ae61fb42d41136fdf1d1733c9bdd7bf6410bbe676ebb03a09e5eaa0";
    int commitCalls;
    boolean injected;

    @Override void commitVerifiedParameters(HighFunction high,int count) throws Exception {
        commitCalls++;
        throw new IllegalStateException("Control forbids parameter commit");
    }
    @Override HighFunction highFunction(ghidra.program.model.listing.Function f) {
        if(injected) throw new IllegalStateException("Control forbids decompilation after injection");
        return super.highFunction(f);
    }
    String hash(byte[] value) throws Exception {
        return HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(value));
    }
    String variable(Variable v) {
        return v.getName()+":"+v.getDataType().getPathName()+":"+v.getVariableStorage()+":"+v.getSource();
    }
    String snapshot() throws Exception {
        TreeSet<String> records=new TreeSet<>(); int count=0;
        // Whole tiny owned listing, capped. Immutable strings, not live object references.
        var units=currentProgram.getListing().getCodeUnits(true);
        while(units.hasNext()) {
            monitor.checkCancelled(); if(++count>100000) throw new IllegalStateException("Snapshot listing limit");
            var u=units.next();
            String r="unit:"+u.getMinAddress()+":"+u.getMaxAddress()+":"+u.getLength()+":"+
                u.getClass().getName()+":"+HexFormat.of().formatHex(u.getBytes());
            if(u instanceof Instruction i) {
                r+=":"+i.getFlowType()+":"+i.getFlowOverride()+":"+i.getFallThrough();
                for(var target:i.getFlows())r+=":"+target;
            }
            records.add(r);
        }
        var functions=currentProgram.getFunctionManager().getFunctions(true); count=0;
        while(functions.hasNext()) {
            monitor.checkCancelled(); if(++count>4096)throw new IllegalStateException("Snapshot function limit");
            var f=functions.next();String r="function:"+f.getEntryPoint()+":"+f.getName()+":"+
                f.getPrototypeString(false,true)+":"+f.getSignatureSource()+":"+f.getCallingConventionName()+":"+
                f.hasCustomVariableStorage()+":"+variable(f.getReturn());
            var ranges=f.getBody().getAddressRanges(true);
            while(ranges.hasNext()){var range=ranges.next();r+=":"+range.getMinAddress()+"-"+range.getMaxAddress();}
            for(var p:f.getParameters())r+=":"+variable(p);
            records.add(r);
        }
        for(String name:new String[]{"caller","callee"}) {
            JsonObject p=trial.getAsJsonObject(name);long lo=value(p,"entry_va"),hi=value(p,"end_va_exclusive");
            if(lo%4!=0||hi%4!=0||hi<=lo||hi-lo>8192||p.get("length").getAsLong()!=hi-lo)
                throw new IllegalStateException("Control extent invalid");
            byte[] bytes=new byte[(int)(hi-lo)];
            if(currentProgram.getMemory().getBytes(address(text(p,"entry_va")),bytes)!=bytes.length ||
               !hash(bytes).equals(text(p,"extent_sha256"))) throw new IllegalStateException("Control memory differs");
            records.add("memory:"+name+":"+text(p,"entry_va")+":"+HexFormat.of().formatHex(bytes));
        }
        String result=new Gson().toJson(records);
        if(result.getBytes(StandardCharsets.UTF_8).length>4*1024*1024)throw new IllegalStateException("Snapshot byte limit");
        return result;
    }
    @Override public void run() throws Exception {
        String[] args=getScriptArgs();
        if(args.length!=3||!args[2].equals("25")||isHeadlessAnalysisEnabled()||!"12.2".equals(getGhidraVersion())||
           !OWNED.equals(currentProgram.getExecutableSHA256())||!ARM.equals(currentProgram.getLanguageID().getIdAsString()))
            throw new IllegalStateException("Fixed owned control only");
        Path request=Path.of(args[0]), dir=request.getParent(), output=Path.of(args[1]+".control.json");
        if(Files.size(request)>256*1024||Files.size(dir.resolve("control.json"))>1024)
            throw new IllegalStateException("Control request limit");
        trial=JsonParser.parseString(Files.readString(request)).getAsJsonObject();
        JsonObject spec=JsonParser.parseString(Files.readString(dir.resolve("control.json"))).getAsJsonObject();
        if(!spec.keySet().equals(Set.of("schema","control","request_sha256"))||!CONTROL.equals(text(spec,"schema"))||
           !hash(Files.readAllBytes(request)).equals(text(spec,"request_sha256"))||
           !"prepared".equals(text(trial,"arm"))||!EXPERIMENT.equals(text(trial,"experiment"))||
           !PARAMETERS.equals(text(trial,"policy"))||!OWNED.equals(text(trial,"image_sha256"))||
           !"arm64".equals(text(trial,"arch"))||!"0xc2c".equals(text(trial,"entry_va"))||
           !"0xc2c".equals(text(trial.getAsJsonObject("caller"),"entry_va"))||
           !"0xbec".equals(text(trial.getAsJsonObject("callee"),"entry_va")))
            throw new IllegalStateException("Control request identity differs");
        String kind=text(spec,"control");
        if(!Set.of("prep_digest","prep_rollback","ast_scope").contains(kind))throw new IllegalStateException("Control kind");
        String before,after,refusal;boolean present=false,absent=false;int positives=0;
        if(kind.equals("ast_scope")) {
            // Prepared-only asserted above before superclass can consider recovery.
            super.run();timeout=25;
            before=snapshot();
            HighFunction high=highFunction(internal("0xbec")); // unchanged real positive guard
            positives=checks.size();
            var end=address(text(trial.getAsJsonObject("callee"),"end_va_exclusive"));
            int unique=0,count=0;var ops=high.getPcodeOps();
            while(ops.hasNext()) {
                if(++count>100000)throw new IllegalStateException("Control pcode limit");
                int time=ops.next().getSeqnum().getTime();
                if(time<0||time==Integer.MAX_VALUE)throw new IllegalStateException("Sequence time unavailable");
                unique=Math.max(unique,time+1);
            }
            PcodeOp added=high.newOp(new SequenceNumber(end,unique),PcodeOp.UNIMPLEMENTED,new ArrayList<Varnode>(),null);
            injected=true;ops=high.getPcodeOps();count=0;
            while(ops.hasNext()) {
                if(++count>100001)throw new IllegalStateException("Injected bank limit");
                if(ops.next()==added)present=true;
            }
            if(!present||!added.getSeqnum().getTarget().equals(end))throw new IllegalStateException("Injection not in scanned bank");
            refusal="Native operation outside independently pinned extent";
            try {checkNative(high);throw new IllegalStateException("Scope guard unexpectedly accepted injection");}
            catch(IllegalStateException e) {if(!refusal.equals(e.getMessage()))throw e;}
            if(checks.size()!=positives)throw new IllegalStateException("Rejected graph appended successful check");
            after=snapshot();
            // No graph processing, redecompilation or export follows this point.
        } else {
            before=snapshot();JsonObject caller=trial.getAsJsonObject("caller");
            Path report=dir.resolve("controlled-focus.json"),tail=dir.resolve("control-tail.json");
            if(Files.exists(report)||Files.size(tail)>128*1024)throw new IllegalStateException("Control artifact invalid");
            String expected=text(caller,"extent_sha256");
            if(kind.equals("prep_digest"))expected=(expected.startsWith("0")?"1":"0")+expected.substring(1);
            refusal=kind.equals("prep_digest")?"Program extent bytes differ from the verified slice":"Invalid tail-call source or destination";
            try {
                runScript("MacscopeFocus.java",new String[]{report.toString(),OWNED,text(caller,"entry_va"),
                    text(caller,"end_va_exclusive"),expected,tail.toString(),hash(Files.readAllBytes(tail))});
                throw new IllegalStateException("Preparation unexpectedly succeeded");
            } catch(IllegalStateException e) {if(!refusal.equals(e.getMessage()))throw e;}
            absent=!Files.exists(report);if(!absent)throw new IllegalStateException("Preparation reported success");
            after=snapshot();
        }
        if(!before.equals(after)||commitCalls!=0)throw new IllegalStateException("Control mutated selected observable state");
        JsonObject snapshots=new JsonObject();snapshots.addProperty("before",before);snapshots.addProperty("after",after);
        Files.writeString(dir.resolve("control-snapshots.json"),new Gson().toJson(snapshots),StandardOpenOption.CREATE_NEW);
        JsonObject out=new JsonObject();out.addProperty("schema",CONTROL);out.addProperty("control",kind);
        out.addProperty("image_sha256",OWNED);out.addProperty("request_sha256",text(spec,"request_sha256"));
        out.add("caller",trial.get("caller"));out.add("callee",trial.get("callee"));out.addProperty("status","expected_refusal");
        out.addProperty("refusal",refusal);out.addProperty("before_sha256",hash(before.getBytes(StandardCharsets.UTF_8)));
        out.addProperty("after_sha256",hash(after.getBytes(StandardCharsets.UTF_8)));out.addProperty("commit_calls",commitCalls);
        out.addProperty("inference_attempted",false);out.addProperty("preparation_report_absent",absent);
        out.addProperty("positive_scope_checks",positives);out.add("positive_scope_evidence",checks);out.addProperty("rejected_scope_check_appended",false);
        out.addProperty("injected_operation_present",present);
        out.addProperty("injected_address",kind.equals("ast_scope")?text(trial.getAsJsonObject("callee"),"end_va_exclusive"):null);
        out.addProperty("native_graph_exported",false);out.addProperty("ghidra_version",getGhidraVersion());
        out.addProperty("headless_analysis_enabled",isHeadlessAnalysisEnabled());
        JsonObject runtime=new JsonObject();runtime.addProperty("home",System.getProperty("java.home"));
        runtime.addProperty("version",System.getProperty("java.runtime.version"));runtime.addProperty("arch",System.getProperty("os.arch"));
        out.add("java_runtime",runtime);
        Files.writeString(output,new Gson().toJson(out),StandardOpenOption.CREATE_NEW);
    }
}
