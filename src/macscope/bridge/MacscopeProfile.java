// Trusted pre-analysis profile for full Ghidra 12.2. No input-side scripts.
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Locale;
import java.util.Map;

import com.google.gson.Gson;
import ghidra.app.util.headless.HeadlessScript;
import ghidra.framework.options.Options;
import ghidra.program.model.listing.Program;

public class MacscopeProfile extends HeadlessScript {
    public static final String PROFILE = "macscope-binary-only/1";
    public static final String PARAMETER_PROFILE = "macscope-binary-only-parameters/1";
    public static final String DEEP_PROFILE = "macscope-binary-only-deep/1";
    private static final Map<String, String> DEEP_OPTIONS = Map.of(
        "Reference", "true",
        "Reference.Create Address Tables", "true",
        "Reference.Address Table Alignment", "1",
        "Reference.Address Table Minimum Size", "2",
        "Reference.Relocation Table Guide", "true",
        "Reference.Switch Table References", "false",
        "Aggressive Instruction Finder", "false"
    );
    private static final int MAX_OPTIONS = 4096;

    @Override
    public void run() throws Exception {
        try {
            if (currentProgram == null || !"12.2".equals(getGhidraVersion())) {
                throw new IllegalStateException("Profile requires a loaded Program and Ghidra 12.2");
            }
            String[] args = getScriptArgs();
            boolean deep = args.length == 1 && args[0].equals("deep");
            if (args.length > 1 || (args.length == 1 && !deep && !args[0].equals("parameter-inference"))) {
                throw new IllegalArgumentException("Unsupported Macscope analysis profile");
            }
            boolean inferParameters = args.length == 1;
            String selectedProfile = inferParameters ? PARAMETER_PROFILE : PROFILE;
            if (deep) {
                selectedProfile = DEEP_PROFILE;
            }
            // Reset prior saved/user-specific choices before applying this versioned profile.
            resetAllAnalysisOptions(currentProgram);
            Map<String, String> values = getCurrentAnalysisOptionsAndValues(currentProgram);
            if (values.size() > MAX_OPTIONS) {
                throw new IllegalStateException("Analyzer option count exceeds profile bound");
            }
            List<String> keys = new ArrayList<>(values.keySet());
            Collections.sort(keys);
            List<String> disabled = new ArrayList<>();
            for (int i = 0; i < keys.size() && i < MAX_OPTIONS; i++) {
                monitor.checkCancelled();
                String name = keys.get(i);
                String lower = name.toLowerCase(Locale.ROOT);
                // Conservative binary-only baseline: disable the entire analyzer, not
                // just optional source fetching. This includes demanglers that may
                // launch host tools. The tradeoff is recorded in the result.
                boolean unsafe = lower.contains("dwarf") || lower.contains("pdb") ||
                    lower.contains("source") || lower.contains("demangl") ||
                    lower.contains("external") || lower.contains("library") ||
                    lower.contains("debug") || lower.contains("debuginfod");
                if (unsafe && ("true".equalsIgnoreCase(values.get(name)) ||
                               "false".equalsIgnoreCase(values.get(name)))) {
                    setAnalysisOption(currentProgram, name, "false");
                    disabled.add(name);
                }
            }
            if (inferParameters) {
                setAnalysisOption(currentProgram, "Decompiler Parameter ID", "true");
            }
            if (deep) {
                setAnalysisOption(currentProgram, "Reference.Create Address Tables", "true");
            }
            Map<String, String> effective = getCurrentAnalysisOptionsAndValues(currentProgram);
            String expectedParameterID = inferParameters ? "true" : "false";
            if (!expectedParameterID.equals(effective.get("Decompiler Parameter ID"))) {
                throw new IllegalStateException("Unexpected Decompiler Parameter ID setting");
            }
            if (deep) {
                for (var option : DEEP_OPTIONS.entrySet()) {
                    if (!option.getValue().equals(effective.get(option.getKey()))) {
                        throw new IllegalStateException("Unexpected deep analysis option: " + option.getKey());
                    }
                }
            }
            for (int i = 0; i < disabled.size() && i < MAX_OPTIONS; i++) {
                String name = disabled.get(i);
                if (!"false".equalsIgnoreCase(effective.get(name))) {
                    throw new IllegalStateException("Could not disable analyzer option: " + name);
                }
            }
            Options info = currentProgram.getOptions(Program.PROGRAM_INFO);
            info.setString("Macscope Profile", selectedProfile);
            info.setBoolean("Macscope Parameter Inference", inferParameters);
            info.setString("Macscope Profile Ghidra", getGhidraVersion());
            info.setString("Macscope Disabled Options", new Gson().toJson(disabled));
            info.setBoolean("Macscope Profile Applied", true);
            println("MacscopeProfile: " + selectedProfile + "; disabled " + disabled.size() + " options");
        } catch (Exception e) {
            // Headless may otherwise proceed after a script exception. Explicitly
            // prevent autoanalysis and abort this file if profile setup failed.
            enableHeadlessAnalysis(false);
            setHeadlessContinuationOption(HeadlessContinuationOption.ABORT);
            throw e;
        }
    }
}
