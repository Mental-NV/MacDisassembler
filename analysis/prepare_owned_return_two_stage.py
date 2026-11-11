"""Owned feasibility only: generate two-phase, rollback-verified disposable runtime files.

Usage: python prepare_owned_return_two_stage.py BASELINE_ROOT NEW_DIRECTORY 0xENTRY
No in-place edits, global prototypes, application execution or production option.
"""
import hashlib
import json
from pathlib import Path
import re
import sys

BRIDGE_SHA='212678fe1487e48c7b883a67b721cf5bd50ffbeba2ee60483dae0595cdf62964'
ENGINE_SHA='2903bad69a99795f156bc175c17a0fade576f596e32d2c34d98e658fa2da5416'
KEY='owned-return-feasibility-two-stage-v1'
SNAPSHOT='''    static String ownedSnapshot(ghidra.program.model.listing.Function f) {
        com.google.gson.JsonObject value = new com.google.gson.JsonObject();
        value.addProperty("name", f.getName());
        value.addProperty("entry", f.getEntryPoint().toString());
        value.addProperty("body", f.getBody().toString());
        value.addProperty("signature", f.getSignature().toString());
        value.addProperty("source", f.getSignatureSource().toString());
        value.addProperty("returnType", f.getReturnType().getDisplayName());
        value.addProperty("returnStorage", f.getReturn().getVariableStorage().toString());
        value.addProperty("returnSource", f.getReturn().getSource().toString());
        value.addProperty("convention", f.getCallingConventionName());
        value.addProperty("customStorage", f.hasCustomVariableStorage());
        value.addProperty("varargs", f.hasVarArgs());
        value.addProperty("noReturn", f.hasNoReturn());
        com.google.gson.JsonArray parameters = new com.google.gson.JsonArray();
        for (var p : f.getParameters()) {
            com.google.gson.JsonObject parameter = new com.google.gson.JsonObject();
            parameter.addProperty("name", p.getName());
            parameter.addProperty("type", p.getDataType().getDisplayName());
            parameter.addProperty("storage", p.getVariableStorage().toString());
            parameter.addProperty("source", p.getSource().toString());
            parameters.add(parameter);
        }
        value.add("parameters", parameters);
        return value.toString();
    }

    static String ownedDigest(byte[] bytes) throws Exception {
        return java.util.HexFormat.of().formatHex(java.security.MessageDigest.getInstance("SHA-256").digest(bytes));
    }
'''
VERIFIER='''// OWNED FEASIBILITY ONLY. Default script analysis mode; do not override it.
import ghidra.app.script.GhidraScript;
import java.nio.file.*;
import java.util.*;
public class VerifyOwnedReturn extends GhidraScript {
SNAPSHOT
    public void run() throws Exception {
        Object raw = state.getEnvironmentVar("KEY");
        state.removeEnvironmentVar("KEY"); // One-shot even if verification fails.
        if (!(raw instanceof Map<?,?> context)) throw new IllegalStateException("Missing staged context");
        Path output = Path.of(getScriptArgs()[0]).toAbsolutePath().normalize();
        if (context.get("program") != currentProgram || !output.equals(context.get("output")))
            throw new IllegalStateException("Program or output identity differs");
        UUID.fromString((String)context.get("nonce"));
        var transaction = currentProgram.getCurrentTransactionInfo();
        if (transaction == null || !transaction.getStatus().toString().equals("NOT_DONE") ||
            !transaction.getOpenSubTransactions().equals(List.of(getClass().getName())) ||
            Objects.equals(context.get("transaction"), Long.valueOf(transaction.getID())))
            throw new IllegalStateException("Unexpected pending transaction boundary");
        var entry = currentProgram.getAddressFactory().getDefaultAddressSpace().getAddress((String)context.get("entry"));
        var function = currentProgram.getFunctionManager().getFunctionAt(entry);
        if (function == null || !context.get("before").equals(ownedSnapshot(function)) ||
            !Objects.equals(context.get("binary"), currentProgram.getExecutableSHA256()))
            throw new IllegalStateException("Post-transaction function restoration failed");
        Path staged = (Path)context.get("staged");
        if (!staged.equals(output.resolveSibling(output.getFileName()+".unverified")) ||
            !Files.isRegularFile(staged, LinkOption.NOFOLLOW_LINKS) || Files.exists(output, LinkOption.NOFOLLOW_LINKS))
            throw new IllegalStateException("Unsafe or stale staged result");
        byte[] payload;
        try (var stream = Files.newInputStream(staged, LinkOption.NOFOLLOW_LINKS)) {
            payload = stream.readNBytes(64*1024*1024+1);
        }
        if (payload.length > 64*1024*1024 || !context.get("payload_sha256").equals(ownedDigest(payload)))
            throw new IllegalStateException("Staged result digest differs");
        // All restoration, transaction, identity and byte checks precede acceptance.
        Files.write(output, payload, StandardOpenOption.CREATE_NEW, StandardOpenOption.WRITE);
        println("OWNED_RETURN_ROLLBACK_VERIFIED nonce=" + context.get("nonce") +
                " entry=" + context.get("entry") + " beforeTransaction=" + context.get("transaction") +
                " verificationTransaction=" + transaction.getID() + " payload_sha256=" + context.get("payload_sha256"));
    }
}
'''
OLD='''                if (fromImport) {
                    item = function(f, new BasicBlockModel(currentProgram), opened ? decomp : null, timeout);
                } else {'''


def generate(root, destination, entry):
    if not re.fullmatch(r'0x[0-9a-f]{1,16}',entry):raise ValueError('Require one explicitly bound owned entry')
    bridge=(root/'src/macscope/bridge/MacscopeBridge.java').read_bytes()
    engine=(root/'src/macscope/engine.py').read_bytes()
    if hashlib.sha256(bridge).hexdigest()!=BRIDGE_SHA or hashlib.sha256(engine).hexdigest()!=ENGINE_SHA:
        raise ValueError('Unexpected baseline source')
    text=bridge.decode()
    assert text.count(OLD)==1 and text.count('        writeAtomic(output);')==1
    text=text.replace('    void functions(int limit,', '    Path ownedOutput;\n'+SNAPSHOT+'\n    void functions(int limit,')
    text=text.replace('        Path output = Path.of(args[0]).toAbsolutePath().normalize();',
                      '        Path output = Path.of(args[0]).toAbsolutePath().normalize();\n        ownedOutput = output;')
    replacement='''                if (fromImport) {
                    if (!entry.equals("ENTRY") || !f.getName().contains("OwnedReturnChannels") ||
                        state.getEnvironmentVar("KEY") != null)
                        throw new IllegalStateException("Not the explicitly bound owned experiment");
                    var transaction = currentProgram.getCurrentTransactionInfo();
                    if (transaction == null) throw new IllegalStateException("Missing outer transaction");
                    Map<String,Object> context = new java.util.HashMap<>();
                    context.put("program", currentProgram); context.put("binary", currentProgram.getExecutableSHA256());
                    context.put("entry", entry.substring(2)); context.put("before", ownedSnapshot(f));
                    context.put("output", ownedOutput); context.put("nonce", java.util.UUID.randomUUID().toString());
                    context.put("transaction", Long.valueOf(transaction.getID()));
                    state.addEnvironmentVar("KEY", context);
                    int experimentTransaction = currentProgram.startTransaction("Owned return assumption (rollback)");
                    try {
                        f.setReturnType(scalarHintType("int64_t"), SourceType.USER_DEFINED);
                        decomp.flushCache();
                        item = function(f, new BasicBlockModel(currentProgram), opened ? decomp : null, timeout);
                    } finally {
                        currentProgram.endTransaction(experimentTransaction, false);
                    }
                    // No acceptance here: verifier runs only after this script's outer transaction ends.
                } else {'''.replace('ENTRY',entry).replace('KEY',KEY)
    text=text.replace(OLD,replacement)
    text=text.replace('        writeAtomic(output);','''        if (fromImport) {
            @SuppressWarnings("unchecked")
            Map<String,Object> context = (Map<String,Object>)state.getEnvironmentVar("KEY");
            if (context == null) throw new IllegalStateException("Missing owned context");
            Path staged = output.resolveSibling(output.getFileName()+".unverified");
            if (Files.exists(output, LinkOption.NOFOLLOW_LINKS) || Files.exists(staged, LinkOption.NOFOLLOW_LINKS))
                throw new IllegalStateException("Owned result paths must be fresh");
            writeAtomic(staged);
            context.put("staged", staged); context.put("payload_sha256", ownedDigest(Files.readAllBytes(staged)));
        } else writeAtomic(output);'''.replace('KEY',KEY))
    command="    argv += ['-max-cpu', '1', '-analysisTimeoutPerFile', str(args.timeout), '-log',"
    source=engine.decode();assert source.count(command)==1
    source=source.replace(command,"    if from_import:\n        argv += ['-postScript', 'VerifyOwnedReturn.java', str(outfile)]\n"+command)
    files={'MacscopeBridge.java':text, 'VerifyOwnedReturn.java':VERIFIER.replace('SNAPSHOT',SNAPSHOT).replace('KEY',KEY), 'engine.py':source}
    destination.mkdir(mode=0o700) # Refuse reuse/overwrite of a previous run directory.
    hashes={}
    for name,content in files.items():
        payload=content.encode();hashes[name]=hashlib.sha256(payload).hexdigest()
        with (destination/name).open('xb') as stream:stream.write(payload)
    manifest={'experiment_only':True,'explicit_owned_entry':entry,'explicit_return_assumption':'int64_t',
              'baseline_bridge_sha256':BRIDGE_SHA,'baseline_engine_sha256':ENGINE_SHA,'generated_sha256':hashes}
    (destination/'manifest.json').write_text(json.dumps(manifest,indent=2)+'\n')
    print(json.dumps(manifest,indent=2))


if __name__=='__main__':generate(Path(sys.argv[1]),Path(sys.argv[2]),sys.argv[3])
