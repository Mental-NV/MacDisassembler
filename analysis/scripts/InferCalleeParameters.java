// Disposable experiment only. Never run automatically in the production CLI.
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;
import com.google.gson.Gson;
import com.google.gson.JsonObject;
import ghidra.app.util.headless.HeadlessScript;
import ghidra.app.decompiler.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.pcode.HighFunctionDBUtil;
import ghidra.program.model.symbol.SourceType;

public class InferCalleeParameters extends HeadlessScript {
    @Override
    public void run() throws Exception {
        String[] args = getScriptArgs();
        if (args.length != 3) throw new IllegalArgumentException("Expected symbol, profile and evidence path");
        Function found = null;
        for (Function function : currentProgram.getFunctionManager().getFunctions(true)) {
            monitor.checkCancelled();
            if (function.getName().equals(args[0])) {
                if (found != null) throw new IllegalStateException("Ambiguous target");
                found = function;
            }
        }
        if (found == null || found.isExternal() || found.isThunk())
            throw new IllegalStateException("Missing internal target");
        JsonObject evidence = new JsonObject();
        evidence.addProperty("target", found.getName());
        evidence.addProperty("entry", found.getEntryPoint().toString());
        evidence.addProperty("signature_before", found.getSignature().toString());
        evidence.addProperty("return_type_before", found.getReturnType().getPathName());
        DecompInterface decompiler = new DecompInterface();
        try {
            decompiler.toggleSyntaxTree(true);
            decompiler.toggleCCode(true);
            if (!decompiler.openProgram(currentProgram))
                throw new IllegalStateException(decompiler.getLastMessage());
            DecompileResults result = decompiler.decompileFunction(found, 30, monitor);
            if (!result.decompileCompleted() || result.getHighFunction() == null)
                throw new IllegalStateException(result.getErrorMessage());
            evidence.addProperty("inferred_signature", result.getDecompiledFunction().getSignature());
            HighFunctionDBUtil.commitParamsToDatabase(result.getHighFunction(), true,
                HighFunctionDBUtil.ReturnCommitOption.NO_COMMIT, SourceType.ANALYSIS);
            evidence.addProperty("parameter_count", found.getParameterCount());
            evidence.addProperty("signature_after", found.getSignature().toString());
            evidence.addProperty("return_type_after", found.getReturnType().getPathName());
            currentProgram.getOptions(Program.PROGRAM_INFO).setString("Macscope Profile", args[1]);
            Files.writeString(Path.of(args[2]), new Gson().toJson(evidence),
                              StandardOpenOption.CREATE_NEW, StandardOpenOption.WRITE);
        } finally {
            decompiler.dispose();
        }
    }
}
