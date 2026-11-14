// Owned-only experiment, not a production bridge or isolated focused receipt.
import com.google.gson.*;
import ghidra.app.util.headless.HeadlessScript;
import ghidra.app.cmd.disassemble.DisassembleCommand;
import ghidra.app.decompiler.*;
import ghidra.program.model.address.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.symbol.SourceType;
import java.nio.file.*;
import java.security.MessageDigest;
import java.util.*;

public class OwnedSharedImport extends HeadlessScript {
    String hex(Address a) { return "0x" + Long.toUnsignedString(a.getOffset(),16); }
    JsonObject snapshot(Function f) throws Exception {
        JsonObject r = new JsonObject();
        r.addProperty("entry",hex(f.getEntryPoint()));
        r.addProperty("name",f.getName());
        r.addProperty("signature",f.getSignature().toString());
        JsonArray body = new JsonArray();
        for (AddressRange range : f.getBody()) {
            JsonArray pair = new JsonArray();pair.add(hex(range.getMinAddress()));pair.add(hex(range.getMaxAddress()));body.add(pair);
        }
        r.add("body_ranges",body);
        JsonArray instructions = new JsonArray();
        var iter = currentProgram.getListing().getInstructions(f.getBody(),true);
        while(iter.hasNext()) {
            var i=iter.next(); JsonObject row=new JsonObject();
            row.addProperty("address",hex(i.getAddress()));
            row.addProperty("bytes",HexFormat.of().formatHex(i.getBytes()));
            row.addProperty("flow",i.getFlowType().toString());
            instructions.add(row);
        }
        r.add("instructions",instructions);return r;
    }
    public void run() throws Exception {
        String[] args=getScriptArgs();
        if(args.length!=2 || isHeadlessAnalysisEnabled() || !getGhidraVersion().equals("12.2")) throw new IllegalArgumentException("Invalid owned experiment mode");
        Path planPath=Path.of(args[0]);if(Files.size(planPath)>32768)throw new IllegalArgumentException("Plan oversized");
        var plan=JsonParser.parseString(Files.readString(planPath)).getAsJsonObject();
        if(!plan.get("input_sha256").getAsString().equals(currentProgram.getExecutableSHA256()))throw new IllegalArgumentException("Input differs");
        var spans=plan.getAsJsonArray("spans");
        if(spans.size()!=3)throw new IllegalArgumentException("Exactly three owned entries required");
        var space=currentProgram.getAddressFactory().getDefaultAddressSpace();
        Address[] starts=new Address[3],ends=new Address[3];AddressSet[] bodies=new AddressSet[3];
        for(int i=0;i<3;i++) {
            var span=spans.get(i).getAsJsonObject();
            starts[i]=space.getAddress(span.get("entry_va").getAsString().substring(2));
            ends[i]=space.getAddress(span.get("end_va_exclusive").getAsString().substring(2));
            long size=ends[i].subtract(starts[i]);
            if(size<1 || size>8192 || (i>0 && starts[i].compareTo(ends[i-1])<0))throw new IllegalArgumentException("Invalid/overlapping span");
            var block=currentProgram.getMemory().getBlock(starts[i]);
            if(block==null || !block.isExecute() || !block.contains(ends[i].subtract(1)))throw new IllegalArgumentException("Nonexecuting span");
            byte[] bytes=new byte[(int)size];
            if(currentProgram.getMemory().getBytes(starts[i],bytes)!=size || !HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(bytes)).equals(span.get("extent_sha256").getAsString()))throw new IllegalArgumentException("Byte proof differs");
            var existing=currentProgram.getFunctionManager().getFunctionsOverlapping(new AddressSet(starts[i],ends[i].subtract(1)));
            while(existing.hasNext()) {
                var f=existing.next();if(!f.getEntryPoint().equals(starts[i]) || f.isExternal() || f.isThunk() || !new AddressSet(starts[i],ends[i].subtract(1)).contains(f.getBody()))throw new IllegalArgumentException("Existing function conflict");
            }
        }
        var order=plan.getAsJsonArray("preparation_order");
        if(order.size()!=3)throw new IllegalArgumentException("Order size");
        Set<Integer> seen=new HashSet<>();for(var v:order){int n=v.getAsInt();if(n<0||n>2||!seen.add(n))throw new IllegalArgumentException("Order invalid");}
        var calls=plan.getAsJsonArray("call_order");if(calls.size()<1 || calls.size()>6)throw new IllegalArgumentException("Too many calls");
        for(var v:calls){int n=v.getAsInt();if(n<0||n>2)throw new IllegalArgumentException("Invalid call");}
        int transaction=currentProgram.startTransaction("Owned collective preparation");boolean success=false;
        try {
            for(var v:order) {
                monitor.checkCancelled();int i=v.getAsInt();var allowed=new AddressSet(starts[i],ends[i].subtract(1));
                new DisassembleCommand(starts[i],allowed,true).applyTo(currentProgram,monitor);
                if(getInstructionAt(starts[i])==null)throw new IllegalArgumentException("Undecoded entry");
                bodies[i]=new AddressSet();var instructions=currentProgram.getListing().getInstructions(allowed,true);
                while(instructions.hasNext()) {var ins=instructions.next();if(!allowed.contains(ins.getMinAddress(),ins.getMaxAddress()))throw new IllegalArgumentException("Cross-boundary instruction");bodies[i].addRange(ins.getMinAddress(),ins.getMaxAddress());}
                if(bodies[i].getNumAddresses()!=ends[i].subtract(starts[i]))throw new IllegalArgumentException("Owned fixture decoding gap");
            }
            for(int i=0;i<3;i++)for(int j=0;j<i;j++)if(bodies[i].intersects(bodies[j]))throw new IllegalArgumentException("Body overlap");
            for(var v:order) {int i=v.getAsInt();var manager=currentProgram.getFunctionManager();var f=manager.getFunctionAt(starts[i]);if(f==null)f=manager.createFunction(null,starts[i],bodies[i],SourceType.USER_DEFINED);else f.setBody(bodies[i]);if(f==null)throw new IllegalArgumentException("Function creation failed");}
            success=true;
        } finally {currentProgram.endTransaction(transaction,success);}
        JsonArray prepared=new JsonArray();for(var a:starts)prepared.add(snapshot(currentProgram.getFunctionManager().getFunctionAt(a)));
        DecompInterface decompiler=new DecompInterface();JsonArray results=new JsonArray();
        try {
            decompiler.setOptions(new DecompileOptions());decompiler.toggleCCode(true);decompiler.toggleSyntaxTree(true);decompiler.setSimplificationStyle("decompile");
            if(!decompiler.openProgram(currentProgram))throw new IllegalStateException("Cannot open decompiler");
            for(var v:calls) {
                monitor.checkCancelled();var f=currentProgram.getFunctionManager().getFunctionAt(starts[v.getAsInt()]);
                var r=decompiler.decompileFunction(f,15,monitor);var row=snapshot(f);
                row.addProperty("completed",r.decompileCompleted());row.addProperty("error",r.getErrorMessage());
                row.addProperty("pseudocode",r.getDecompiledFunction()==null?null:r.getDecompiledFunction().getC());results.add(row);
            }
        } finally {decompiler.dispose();}
        JsonObject output=new JsonObject();output.addProperty("schema","owned-shared-import/1");output.addProperty("semantics","shared-import-preparation");output.add("prepared",prepared);output.add("calls",results);
        String text=new Gson().toJson(output);if(text.length()>1024*1024)throw new IllegalArgumentException("Output oversized");Files.writeString(Path.of(args[1]),text,StandardOpenOption.CREATE_NEW);
    }
}
