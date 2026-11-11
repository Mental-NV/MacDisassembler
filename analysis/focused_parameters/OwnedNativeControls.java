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
import java.util.TreeMap;
import java.util.Comparator;
import com.google.gson.JsonArray;
import com.google.gson.Gson;
import com.google.gson.GsonBuilder;
import com.google.gson.JsonObject;
import com.google.gson.JsonParser;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.Variable;
import ghidra.program.model.pcode.HighFunction;
import ghidra.program.model.pcode.PcodeOp;
import ghidra.program.model.pcode.SequenceNumber;
import ghidra.program.model.pcode.Varnode;

public class OwnedNativeControls extends OwnedScopedParameters {
    static final Gson JSON=new GsonBuilder().serializeNulls().create();
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
    record Unit(String space,long start,int length,String kind,String blockKey,String bytes,String flow) {}
    String snapshot() throws Exception {
        TreeMap<String,JsonObject> blockTable=new TreeMap<>();TreeSet<String> kindTable=new TreeSet<>();
        ArrayList<Unit> captured=new ArrayList<>();TreeSet<String> functionRows=new TreeSet<>();int count=0;
        var units=currentProgram.getListing().getCodeUnits(true);
        while(units.hasNext()) {
            monitor.checkCancelled();if(++count>100000)throw new IllegalStateException("Snapshot listing limit");
            var u=units.next();var lo=u.getMinAddress();var hi=u.getMaxAddress();
            var block=currentProgram.getMemory().getBlock(lo);
            if(block==null||block.isMapped()||!block.contains(hi)||currentProgram.getMemory().getBlock(hi)!=block||
               !lo.getAddressSpace().equals(hi.getAddressSpace())||!lo.getAddressSpace().equals(block.getStart().getAddressSpace())||
               !lo.getAddressSpace().equals(block.getEnd().getAddressSpace()))
                throw new IllegalStateException("Unknown, mapped, mixed-space or cross-block code unit");
            long start=lo.getOffset();int length=u.getLength();
            if(start<0||length<1||length>4*1024*1024||start>Long.MAX_VALUE-length+1||
               hi.getOffset()!=start+length-1||block.getStart().getOffset()<0||block.getEnd().getOffset()<0)
                throw new IllegalStateException("Code unit range mismatch");
            String space=lo.getAddressSpace().getName(),kind=u.getClass().getName();
            String key=space+"\000"+String.format("%016x",block.getStart().getOffset())+"\000"+
                String.format("%016x",block.getEnd().getOffset())+"\000"+block.getName();
            JsonObject bd=new JsonObject();bd.addProperty("space",space);bd.addProperty("name",block.getName());
            bd.addProperty("start",block.getStart().getOffset());bd.addProperty("end",block.getEnd().getOffset());
            bd.addProperty("initialized",block.isInitialized());bd.addProperty("mapped",false);
            if(blockTable.containsKey(key)&&!blockTable.get(key).equals(bd))throw new IllegalStateException("Conflicting block metadata");
            blockTable.put(key,bd);kindTable.add(kind);
            if(blockTable.size()>4096||kindTable.size()>4096)throw new IllegalStateException("Snapshot table limit");
            String bytes=null;
            if(block.isInitialized()) {
                byte[] read=u.getBytes();if(read.length!=length)throw new IllegalStateException("Incomplete initialized bytes");
                bytes=HexFormat.of().formatHex(read);
            }
            String flow="";
            if(u instanceof Instruction i) {
                flow=i.getFlowType()+":"+i.getFlowOverride()+":"+i.getFallThrough();
                for(var target:i.getFlows())flow+=":"+target;
            }
            captured.add(new Unit(space,start,length,kind,key,bytes,flow));
        }
        captured.sort(Comparator.comparing(Unit::space).thenComparingLong(Unit::start));
        JsonArray blocks=new JsonArray(),kinds=new JsonArray(),rows=new JsonArray();
        ArrayList<String> blockKeys=new ArrayList<>(blockTable.keySet()),kindKeys=new ArrayList<>(kindTable);
        for(String key:blockKeys)blocks.add(blockTable.get(key));for(String kind:kindKeys)kinds.add(kind);
        String previousSpace=null;long previousEnd=-1;
        for(Unit u:captured) {
            if(u.space().equals(previousSpace)&&u.start()<=previousEnd)throw new IllegalStateException("Overlapping units");
            previousSpace=u.space();previousEnd=u.start()+u.length()-1;
            JsonArray row=new JsonArray();row.add(u.space());row.add(u.start());row.add(u.length());
            row.add(kindKeys.indexOf(u.kind()));row.add(blockKeys.indexOf(u.blockKey()));
            if(u.bytes()==null)row.add(com.google.gson.JsonNull.INSTANCE);else row.add(u.bytes());
            row.add(u.flow());rows.add(row);
        }
        var functions=currentProgram.getFunctionManager().getFunctions(true);count=0;
        while(functions.hasNext()) {
            monitor.checkCancelled();if(++count>4096)throw new IllegalStateException("Snapshot function limit");
            var f=functions.next();String r="function:"+f.getEntryPoint()+":"+f.getName()+":"+
                f.getPrototypeString(false,true)+":"+f.getSignatureSource()+":"+f.getCallingConventionName()+":"+
                f.hasCustomVariableStorage()+":"+variable(f.getReturn());
            var ranges=f.getBody().getAddressRanges(true);
            while(ranges.hasNext()){var range=ranges.next();r+=":"+range.getMinAddress()+"-"+range.getMaxAddress();}
            for(var param:f.getParameters())r+=":"+variable(param);functionRows.add(r);
        }
        JsonObject memory=new JsonObject();
        for(String name:new String[]{"caller","callee"}) {
            JsonObject p=trial.getAsJsonObject(name);long lo=value(p,"entry_va"),hi=value(p,"end_va_exclusive");
            if(lo%4!=0||hi%4!=0||hi<=lo||hi-lo>8192||p.get("length").getAsLong()!=hi-lo)
                throw new IllegalStateException("Control extent invalid");
            byte[] bytes=new byte[(int)(hi-lo)];
            if(currentProgram.getMemory().getBytes(address(text(p,"entry_va")),bytes)!=bytes.length||
               !hash(bytes).equals(text(p,"extent_sha256")))throw new IllegalStateException("Control memory differs");
            JsonObject row=new JsonObject();row.addProperty("entry_va",text(p,"entry_va"));
            row.addProperty("bytes",HexFormat.of().formatHex(bytes));memory.add(name,row);
        }
        JsonObject inventory=new JsonObject();inventory.addProperty("schema","macscope-owned-control-inventory/2");
        inventory.add("blocks",blocks);inventory.add("kinds",kinds);inventory.add("units",rows);
        inventory.add("functions",JSON.toJsonTree(functionRows));inventory.add("memory",memory);
        String result=JSON.toJson(inventory);
        if(result.getBytes(StandardCharsets.UTF_8).length>4*1024*1024)throw new IllegalStateException("Snapshot byte limit");
        return result;
    }
    JsonObject initializeControl(String[] args) throws Exception {
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
        return spec;
    }

    @Override public void run() throws Exception {
        String[] args=getScriptArgs();JsonObject spec=initializeControl(args);
        Path request=Path.of(args[0]),dir=request.getParent();
        String kind=text(spec,"control");
        String before,refusal;boolean present=false,absent=false;int positives=0;
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
        }
        if(commitCalls!=0)throw new IllegalStateException("Control attempted commit");
        JsonObject out=new JsonObject();out.addProperty("schema",CONTROL);out.addProperty("control",kind);
        out.addProperty("image_sha256",OWNED);out.addProperty("request_sha256",text(spec,"request_sha256"));
        out.add("caller",trial.get("caller"));out.add("callee",trial.get("callee"));out.addProperty("status","refusal_observed");
        out.addProperty("refusal",refusal);out.addProperty("before_sha256",hash(before.getBytes(StandardCharsets.UTF_8)));
        out.addProperty("commit_calls",commitCalls);
        out.addProperty("inference_attempted",false);out.addProperty("preparation_report_absent",absent);
        out.addProperty("positive_scope_checks",positives);out.add("positive_scope_evidence",checks);out.addProperty("rejected_scope_check_appended",false);
        out.addProperty("injected_operation_present",present);
        out.addProperty("injected_address",kind.equals("ast_scope")?text(trial.getAsJsonObject("callee"),"end_va_exclusive"):null);
        out.addProperty("native_graph_exported",false);out.addProperty("ghidra_version",getGhidraVersion());
        out.addProperty("headless_analysis_enabled",isHeadlessAnalysisEnabled());
        JsonObject runtime=new JsonObject();runtime.addProperty("home",System.getProperty("java.home"));
        runtime.addProperty("version",System.getProperty("java.runtime.version"));runtime.addProperty("arch",System.getProperty("os.arch"));
        out.add("java_runtime",runtime);
        JsonObject stage=new JsonObject();stage.addProperty("schema","macscope-owned-native-control-stage/1");
        stage.addProperty("status","refusal_observed");stage.addProperty("control_request_sha256",hash(Files.readAllBytes(dir.resolve("control.json"))));
        stage.addProperty("before",before);stage.add("observation",out);
        Files.writeString(dir.resolve("control-stage.json"),JSON.toJson(stage),StandardOpenOption.CREATE_NEW);
        // Return normally: GhidraScript owns transaction completion. Stage is NOT a pass.

    }
}
