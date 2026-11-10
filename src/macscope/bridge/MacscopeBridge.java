// Narrow, bounded exporter of a real Ghidra Program. Ghidra 12.2 public APIs.
// analyzeHeadless ... -postScript MacscopeBridge.java OUTPUT MODE MAXFUNCS TIMEOUT [MODE_ARGUMENTS]
// MODE: import (no function work), analyze (post-analysis), query (read-only).
// The runner owns import/process/readOnly/noanalysis flags and project locking.
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.nio.ByteBuffer;
import java.nio.charset.CharacterCodingException;
import java.nio.charset.Charset;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.LinkOption;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;
import java.nio.file.attribute.PosixFilePermissions;
import java.security.MessageDigest;
import java.util.ArrayList;
import java.util.Collections;
import java.util.HashMap;
import java.util.HexFormat;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Objects;
import java.util.Set;
import java.util.TreeMap;
import java.util.TreeSet;
import java.util.regex.Pattern;

import com.google.gson.Gson;
import com.google.gson.GsonBuilder;
import com.google.gson.JsonArray;
import com.google.gson.JsonElement;
import com.google.gson.JsonNull;
import com.google.gson.JsonObject;
import com.google.gson.JsonParser;
import ghidra.app.decompiler.ClangFieldToken;
import ghidra.app.decompiler.ClangFuncNameToken;
import ghidra.app.decompiler.ClangLabelToken;
import ghidra.app.decompiler.ClangLine;
import ghidra.app.decompiler.ClangToken;
import ghidra.app.decompiler.ClangTypeToken;
import ghidra.app.decompiler.ClangVariableToken;
import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileOptions;
import ghidra.app.decompiler.DecompileResults;
import ghidra.app.decompiler.DecompiledFunction;
import ghidra.app.decompiler.PrettyPrinter;
import ghidra.app.util.headless.HeadlessScript;
import ghidra.framework.options.Options;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressFormatException;
import ghidra.program.model.address.AddressFormatException;
import ghidra.program.model.address.AddressIterator;
import ghidra.program.model.address.AddressRange;
import ghidra.program.model.address.AddressRangeIterator;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.block.BasicBlockModel;
import ghidra.program.model.block.CodeBlock;
import ghidra.program.model.block.CodeBlockIterator;
import ghidra.program.model.block.CodeBlockReference;
import ghidra.program.model.block.CodeBlockReferenceIterator;
import ghidra.program.model.listing.CodeUnit;
import ghidra.program.model.data.AbstractIntegerDataType;
import ghidra.program.model.data.AbstractFloatDataType;
import ghidra.program.model.data.BooleanDataType;
import ghidra.program.model.data.CategoryPath;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.EndianSettingsDefinition;
import ghidra.program.model.data.PointerDataType;
import ghidra.program.model.data.StructureDataType;
import ghidra.program.model.data.StringDataInstance;
import ghidra.program.model.data.TerminatedStringDataType;
import ghidra.program.model.data.VoidDataType;
import ghidra.program.model.listing.Data;
import ghidra.program.model.listing.DataIterator;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionIterator;
import ghidra.program.model.listing.FunctionManager;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.InstructionIterator;
import ghidra.program.model.listing.Parameter;
import ghidra.program.model.listing.ParameterImpl;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.model.mem.MemoryBlockSourceInfo;
import ghidra.program.model.mem.MemoryAccessException;
import ghidra.program.model.symbol.ExternalLocation;
import ghidra.program.model.symbol.IllegalCharCppTransformer;
import ghidra.program.model.symbol.Reference;
import ghidra.program.model.symbol.ReferenceIterator;
import ghidra.program.model.symbol.SourceType;
import ghidra.program.model.symbol.Symbol;
import ghidra.program.model.symbol.SymbolIterator;
import ghidra.program.model.symbol.SymbolTable;
import ghidra.program.model.symbol.SymbolType;
import ghidra.util.StringUtilities;

public class MacscopeBridge extends HeadlessScript {
    static final String SCHEMA = "macscope-bridge/1";
    static final String VERSION = "1.15.0";
    boolean focusedQuery = false;
    static final String HINT_IDENTIFIER = "[A-Za-z_][A-Za-z0-9_]{0,47}";
    static final Pattern HINT_STRUCT = Pattern.compile("(struct (" + HINT_IDENTIFIER + ")\\{([^{}]+)\\})(\\*{0,2})");
    static final Pattern HINT_FIELD = Pattern.compile("(" + HINT_IDENTIFIER + "):(.+)");
    static final String PROFILE = "macscope-binary-only/1";
    static final String PARAMETER_PROFILE = "macscope-binary-only-parameters/1";
    static final String DEEP_PROFILE = "macscope-binary-only-deep/1";
    static final int MAX_INSTRUCTIONS = 2000, MAX_BLOCKS = 500, MAX_EDGES = 500;
    static final int MAX_XREFS = 200, MAX_RANGES = 512, MAX_SECTIONS = 2048;
    static final int MAX_ENTRY_SYMBOLS = 32;
    static final int MAX_SYMBOLS = 10000, MAX_STRINGS = 5000, MAX_SCAN = 100000;
    static final int MAX_IMAGE_REFS = 16000, MAX_COMPUTED_SITES = 10000;
    static final int MAX_OPTIONS = 4096, MAX_TEXT = 4096, MAX_PSEUDOCODE = 1048576;
    static final int MAX_SPANS_PER_FUNCTION = 1024, MAX_SPANS_PER_JOB = 40000;
    static final String BOUNDARY_POLICY = "macscope-linker-fallthrough-join/1";
    static final String MANUAL_BOUNDARY_POLICY = "macscope-manual-function-boundaries/1";
    static final int MAX_LINKER_STARTS = 10000, MAX_BOUNDARY_CANDIDATES = 128;
    static final int MAX_BOUNDARY_BYTES = 65536, MAX_BOUNDARY_REFERENCES = 10000;
    static final long MAX_OUTPUT = 64L * 1024 * 1024;
    static final long PAYLOAD_BUDGET = 56L * 1024 * 1024;
    static final long METADATA_BUDGET = 16L * 1024 * 1024;
    static final Gson JSON = new GsonBuilder().serializeNulls().disableHtmlEscaping().create();

    final JsonObject root = new JsonObject();
    final JsonArray errors = new JsonArray(), warnings = new JsonArray();
    final JsonObject coverage = new JsonObject();
    final JsonObject summary = new JsonObject();
    final JsonObject decompilerTiming = new JsonObject();
    final JsonArray decompileCalls = new JsonArray();
    long retainedBytes = 0;
    boolean partial = false, fatal = false, textTruncated = false;
    int attempted = 0, completed = 0, timedOut = 0, failed = 0, cancelled = 0, notRequested = 0;
    int retainedSpans = 0;
    String mode, decompilerError;

    @Override
    public void run() throws Exception {
        String[] args = getScriptArgs();
        if (args.length < 4 || args.length > 6) {
            throw new IllegalArgumentException("Usage: MacscopeBridge.java OUTPUT import|analyze|query MAXFUNCS FUNCTION_TIMEOUT [BOUNDARY_REQUEST | QUERY_ENTRY [TYPE_HINTS | --from-import]]");
        }
        mode = args[1];
        if (!mode.equals("import") && !mode.equals("analyze") && !mode.equals("query")) {
            throw new IllegalArgumentException("Unsupported bridge mode: " + mode);
        }
        int maxFunctions = boundedInt(args[2], 1, 10000, "MAXFUNCS");
        int timeout = boundedInt(args[3], 1, 300, "FUNCTION_TIMEOUT");
        Path boundaries = mode.equals("analyze") && args.length == 5 ? Path.of(args[4]) : null;
        String entry = args.length >= 5 && boundaries == null ? args[4] : null;
        boolean fromImport = args.length == 6 && "--from-import".equals(args[5]);
        focusedQuery = fromImport;
        Path typeHints = args.length == 6 && !fromImport ? Path.of(args[5]) : null;
        if (entry != null && (!mode.equals("query") || maxFunctions != 1 || !entry.matches("0x[0-9a-f]{1,16}"))) {
            throw new IllegalArgumentException("Selected decompilation requires query mode and one RAM entry");
        }
        Path output = Path.of(args[0]).toAbsolutePath().normalize();
        root.addProperty("schema", SCHEMA);
        root.addProperty("bridge_version", VERSION);
        root.addProperty("mode", mode);
        if (entry != null) root.addProperty("selected_entry", entry);
        root.addProperty("ghidra_version", getGhidraVersion());
        JsonObject runtime = new JsonObject();
        put(runtime, "home", System.getProperty("java.home"));
        put(runtime, "version", System.getProperty("java.runtime.version"));
        put(runtime, "arch", System.getProperty("os.arch"));
        root.add("java_runtime", runtime);
        root.add("errors", errors);
        root.add("warnings", warnings);
        root.add("coverage", coverage);
        root.add("decompile_summary", summary);
        if (!mode.equals("import")) {
            decompilerTiming.add("open_program", JsonNull.INSTANCE);
            decompilerTiming.add("calls", decompileCalls);
            root.add("decompiler_timing", decompilerTiming);
        }
        root.addProperty("max_funcs", maxFunctions);
        root.addProperty("decompile_timeout_secs", timeout);
        root.add("functions", new JsonArray());
        root.addProperty("function_count_enumerated", 0);
        root.addProperty("functions_truncated", false);
        root.addProperty("output_limit_bytes", MAX_OUTPUT);
        root.addProperty("output_budget_reached", false);
        JsonObject limits = new JsonObject();
        limits.addProperty("functions", maxFunctions);
        limits.addProperty("instructions_per_function", MAX_INSTRUCTIONS);
        limits.addProperty("blocks_per_function", MAX_BLOCKS);
        limits.addProperty("edges_per_function", MAX_EDGES);
        limits.addProperty("xrefs_per_direction_per_function", MAX_XREFS);
        limits.addProperty("reference_source_addresses_per_function", MAX_INSTRUCTIONS);
        if (mode.equals("analyze")) {
            limits.addProperty("image_reference_records", MAX_IMAGE_REFS);
            limits.addProperty("computed_flow_sites", MAX_COMPUTED_SITES);
            limits.addProperty("computed_flow_instruction_scan", MAX_SCAN);
        }
        limits.addProperty("body_ranges_per_function", MAX_RANGES);
        limits.addProperty("entry_symbols_scanned_per_function", MAX_ENTRY_SYMBOLS);
        limits.addProperty("sections", MAX_SECTIONS);
        limits.addProperty("symbols_per_category", MAX_SYMBOLS);
        limits.addProperty("strings", MAX_STRINGS);
        limits.addProperty("defined_data_scan", MAX_SCAN);
        limits.addProperty("option_names_per_category", MAX_OPTIONS);
        limits.addProperty("text_characters", MAX_TEXT);
        limits.addProperty("pseudocode_characters_per_function", MAX_PSEUDOCODE);
        limits.addProperty("address_spans_per_function", MAX_SPANS_PER_FUNCTION);
        limits.addProperty("address_spans_per_job", MAX_SPANS_PER_JOB);
        root.add("limits", limits);
        try {
            if (!"12.2".equals(getGhidraVersion())) {
                throw new IllegalStateException("Bridge is pinned to Ghidra 12.2");
            }
            if (currentProgram == null) throw new IllegalStateException("No loaded Program");
            describeProgram();
            describeOptions();
            verifyMode();
            if (!fatal && boundaries != null) recoverBoundaries(boundaries);
            if (entry == null) {
                sections();
                symbols();
                imports();
                exports();
                strings();
            }
            if (!fatal && !mode.equals("import")) {
                if (typeHints == null) functions(maxFunctions, timeout, entry, fromImport);
                else hintedDecompile(timeout, entry, typeHints);
            }
            else coverage.add("functions", facet(0, 0, false, null,
                mode.equals("import") ? "not_requested" : "failed"));
            if (!fatal && mode.equals("analyze")) imageReferences();
        } catch (Exception e) {
            fatal = true;
            errors.add(error(e));
        }
        summary.addProperty("attempted", attempted);
        summary.addProperty("completed", completed);
        summary.addProperty("timed_out", timedOut);
        summary.addProperty("failed", failed);
        summary.addProperty("cancelled", cancelled);
        summary.addProperty("not_requested", notRequested);
        root.addProperty("strings_or_names_truncated", textTruncated);
        root.addProperty("status", fatal ? "failed" : (partial || textTruncated ? "partial" : "complete"));
        writeAtomic(output);
        println("MacscopeBridge: " + mode + " " + root.get("status").getAsString() +
            "; functions=" + root.get("function_count_enumerated").getAsInt());
    }

    void describeProgram() {
        Program p = currentProgram;
        put(root, "input_name", p.getName());
        put(root, "executable_format", p.getExecutableFormat());
        put(root, "executable_md5", p.getExecutableMD5());
        put(root, "executable_sha256", p.getExecutableSHA256());
        put(root, "language_id", p.getLanguageID().getIdAsString());
        put(root, "compiler_spec_id", p.getCompilerSpec().getCompilerSpecID().getIdAsString());
        put(root, "image_base", address(p.getImageBase()));
        put(root, "min_address", address(p.getMinAddress()));
        put(root, "max_address", address(p.getMaxAddress()));
        root.addProperty("function_count_total_reported_by_engine", p.getFunctionManager().getFunctionCount());
    }

    void describeOptions() throws Exception {
        Options info = currentProgram.getOptions(Program.PROGRAM_INFO);
        JsonObject profile = new JsonObject();
        put(profile, "name", info.getString("Macscope Profile", null));
        put(profile, "ghidra_version", info.getString("Macscope Profile Ghidra", null));
        profile.addProperty("applied", info.getBoolean("Macscope Profile Applied", false));
        profile.addProperty("parameter_inference_enabled", info.getBoolean("Macscope Parameter Inference", false));
        put(profile, "inference_source", "binary-derived; no source prototypes supplied");
        put(profile, "inference_status", mode.equals("query") ? "saved Program; inference not rerun" :
            info.getBoolean("Macscope Parameter Inference", false) ? "enabled during analysis" : "disabled");
        put(profile, "semantic_validation", "not performed");
        profile.addProperty("host_filesystem_sandboxed", false);
        put(profile, "scope", "Binary-only analyzers; runner must also disable loader library/source discovery. This is not a filesystem sandbox.");
        String disabled = info.getString("Macscope Disabled Options", "[]");
        if (disabled.length() <= MAX_PSEUDOCODE) profile.add("disabled_options", JsonParser.parseString(disabled));
        else { profile.add("disabled_options", new JsonArray()); partial = true; }
        root.add("analysis_profile", profile);
        retainedBytes += JSON.toJson(profile).getBytes(StandardCharsets.UTF_8).length;
        Map<String, String> values = getCurrentAnalysisOptionsAndValues(currentProgram);
        List<String> keys = new ArrayList<>(values.keySet());
        Collections.sort(keys);
        JsonObject effective = new JsonObject();
        int n = Math.min(keys.size(), MAX_OPTIONS);
        for (int i = 0; i < n; i++) {
            monitor.checkCancelled();
            String key = keys.get(i);
            if (!appendOption(effective, key, values.get(key))) break;
        }
        root.add("effective_analysis_options", effective);
        coverage.add("effective_analysis_options", facet(effective.size(), keys.size(), keys.size() > effective.size(), null, "complete"));
        JsonObject programOptions = new JsonObject();
        List<String> names = info.getOptionNames();
        int count = Math.min(names.size(), MAX_OPTIONS);
        for (int i = 0; i < count; i++) {
            monitor.checkCancelled();
            String name = names.get(i);
            if (!appendOption(programOptions, name, info.getValueAsString(name))) break;
        }
        root.add("program_info_options", programOptions);
        coverage.add("program_info_options", facet(programOptions.size(), names.size(), names.size() > programOptions.size(), null, "complete"));
    }

    void verifyMode() throws Exception {
        String format = currentProgram.getExecutableFormat();
        String language = currentProgram.getLanguageID().getIdAsString();
        String compiler = currentProgram.getCompilerSpec().getCompilerSpecID().getIdAsString();
        boolean supported = format != null && format.toLowerCase(Locale.ROOT).contains("mach-o") &&
            ((language.equals("AARCH64:LE:64:AppleSilicon") && compiler.equals("default")) ||
             (language.equals("x86:LE:64:default") && compiler.equals("gcc")));
        JsonObject validation = new JsonObject();
        validation.addProperty("supported_loader_and_language", supported);
        validation.addProperty("headless_analysis_enabled", isHeadlessAnalysisEnabled());
        validation.addProperty("analysis_timeout_occurred", analysisTimeoutOccurred());
        validation.addProperty("zero_functions_after_import", currentProgram.getFunctionManager().getFunctionCount() == 0);
        root.add("validation", validation);
        root.addProperty("analysis_timed_out", analysisTimeoutOccurred());
        if (!supported) { fatal = true; errors.add("Expected Mach-O with an arm64 or x86_64 64-bit little-endian language"); }
        if (mode.equals("import")) {
            validation.addProperty("no_autoanalysis", !isHeadlessAnalysisEnabled());
            validation.addProperty("loader_seed_function_count", currentProgram.getFunctionManager().getFunctionCount());
            root.addProperty("loader_seed_function_count", currentProgram.getFunctionManager().getFunctionCount());
            if (isHeadlessAnalysisEnabled()) { fatal = true; errors.add("Import must use -noanalysis"); }
            if (currentProgram.getFunctionManager().getFunctionCount() != 0) {
                warnings.add("The Mach-O loader created seed functions during import. These are expected loader results, not evidence that autoanalysis ran; function export was not requested.");
            }
        } else if (mode.equals("query") && isHeadlessAnalysisEnabled()) {
            fatal = true; errors.add("Query must use -noanalysis and -readOnly");
        } else if (mode.equals("analyze")) {
            Options info = currentProgram.getOptions(Program.PROGRAM_INFO);
            String appliedProfile = info.getString("Macscope Profile", null);
            if ((!PROFILE.equals(appliedProfile) && !PARAMETER_PROFILE.equals(appliedProfile)
                    && !DEEP_PROFILE.equals(appliedProfile)) ||
                !info.getBoolean("Macscope Profile Applied", false)) {
                fatal = true; errors.add("Required binary-only pre-analysis profile was not applied");
            }
        }
        if (analysisTimeoutOccurred()) { partial = true; warnings.add("Ghidra autoanalysis reached its deadline; exported evidence is partial"); }
    }

    record BoundaryCandidate(Function owner, Function competing, Address nextStart) {}

    void recoverBoundaries(Path path) throws Exception {
        if (!isHeadlessAnalysisEnabled()) {
            throw new IllegalStateException("Boundary recovery requires completed headless autoanalysis");
        }
        byte[] content;
        try (InputStream input = Files.newInputStream(path, LinkOption.NOFOLLOW_LINKS)) {
            content = input.readNBytes(262145);
        }
        if (content.length > 262144) throw new IllegalArgumentException("Boundary request exceeds its byte limit");
        JsonObject request = JsonParser.parseString(new String(content, StandardCharsets.UTF_8)).getAsJsonObject();
        if (MANUAL_BOUNDARY_POLICY.equals(request.get("policy").getAsString())) {
            try {
                applyManualBoundaries(request, content);
            } catch (IllegalArgumentException e) {
                root.addProperty("manual_boundary_rejection", e.getMessage());
                throw e;
            }
            return;
        }
        if (!BOUNDARY_POLICY.equals(request.get("policy").getAsString()) ||
            !currentProgram.getExecutableSHA256().equals(request.get("input_sha256").getAsString()) ||
            !address(currentProgram.getImageBase()).equals(request.get("image_base").getAsString())) {
            throw new IllegalArgumentException("Boundary request differs from the loaded image");
        }
        JsonArray addresses = request.getAsJsonArray("linker_starts");
        if (addresses.size() < 2 || addresses.size() > MAX_LINKER_STARTS) {
            throw new IllegalArgumentException("Boundary request has an invalid linker start count");
        }
        TreeSet<Address> starts = new TreeSet<>();
        for (JsonElement item : addresses) {
            monitor.checkCancelled();
            String value = item.getAsString();
            if (!value.matches("0x(?:0|[1-9a-f][0-9a-f]{0,15})") ||
                !starts.add(currentProgram.getAddressFactory().getDefaultAddressSpace().getAddress(value.substring(2)))) {
                throw new IllegalArgumentException("Invalid or duplicate linker start");
            }
        }

        JsonObject report = new JsonObject();
        JsonArray rows = new JsonArray();
        put(report, "policy", BOUNDARY_POLICY);
        put(report, "request_sha256", HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(content)));
        report.add("candidates", rows);
        root.add("boundary_recovery", report);
        FunctionManager manager = currentProgram.getFunctionManager();
        String reason = null;
        if (analysisTimeoutOccurred()) reason = "analysis_timeout";
        else if (manager.getFunctionCount() > MAX_LINKER_STARTS) reason = "function_limit";
        List<BoundaryCandidate> candidates = new ArrayList<>();
        Map<Address, Integer> owners = new HashMap<>();
        if (reason == null) {
            FunctionIterator functions = manager.getFunctions(true);
            while (functions.hasNext()) {
                monitor.checkCancelled();
                Function candidate = functions.next();
                Address entry = candidate.getEntryPoint();
                if (candidate.isExternal() || candidate.isThunk() ||
                    !entry.getAddressSpace().equals(starts.first().getAddressSpace()) ||
                    starts.contains(entry)) continue;
                Address start = starts.lower(entry);
                if (start == null) continue;
                Instruction previous = currentProgram.getListing().getInstructionBefore(entry);
                if (previous == null || !entry.equals(previous.getFallThrough()) ||
                    !entry.equals(previous.getMaxAddress().next())) continue;
                Function owner = manager.getFunctionContaining(previous.getAddress());
                if (owner == null || owner.isExternal() || owner.isThunk() || !start.equals(owner.getEntryPoint()) ||
                    owner.getBody().contains(entry)) continue;
                if (candidates.size() == MAX_BOUNDARY_CANDIDATES) {
                    reason = "candidate_limit";
                    break;
                }
                candidates.add(new BoundaryCandidate(owner, candidate, starts.higher(entry)));
                owners.merge(start, 1, Integer::sum);
            }
        }
        boolean incomplete = reason != null, joined = false;
        if (reason == null) {
            for (BoundaryCandidate candidate : candidates) {
                monitor.checkCancelled();
                Address owner = candidate.owner().getEntryPoint();
                Address competing = candidate.competing().getEntryPoint();
                String outcome = owners.get(owner) == 1 ? joinBoundary(manager, candidate) : "multiple_competing_entries";
                JsonObject row = new JsonObject();
                put(row, "owner", address(owner));
                put(row, "competing", address(competing));
                put(row, "outcome", outcome);
                rows.add(row);
                if (outcome.equals("joined")) joined = true;
                else incomplete = true;
            }
        }
        put(report, "reason", reason);
        put(report, "status", incomplete ? "partial" : "complete");
        partial |= incomplete;
        if (joined) {
            // Do not let Ghidra's automatic post-script pass recreate the removed function.
            enableHeadlessAnalysis(false);
            root.addProperty("function_count_total_reported_by_engine", manager.getFunctionCount());
        }
    }

    record BodyEdit(Address entry, Function original, AddressSet body) {}

    void applyManualBoundaries(JsonObject request, byte[] content) throws Exception {
        if (!request.keySet().equals(Set.of("policy", "input_sha256", "revision", "edits")) ||
                !currentProgram.getExecutableSHA256().equals(request.get("input_sha256").getAsString()) ||
                analysisTimeoutOccurred()) {
            throw new IllegalArgumentException("Boundary edits require completed analysis of the exact image");
        }
        long revision = request.get("revision").getAsLong();
        JsonArray rows = request.getAsJsonArray("edits");
        if (revision < 1 || rows.size() < 1 || rows.size() > 32) {
            throw new IllegalArgumentException("Invalid manual boundary revision or edit count");
        }
        FunctionManager manager = currentProgram.getFunctionManager();
        Map<Address, BodyEdit> edits = new TreeMap<>();
        AddressSet proposed = new AddressSet();
        for (JsonElement element : rows) {
            monitor.checkCancelled();
            JsonObject row = element.getAsJsonObject();
            if (!row.keySet().equals(Set.of("entry", "revision", "before", "body")) ||
                    row.get("revision").getAsLong() < 1 || row.get("revision").getAsLong() > revision) {
                throw new IllegalArgumentException("Invalid manual boundary edit");
            }
            Address entry = manualBoundaryAddress(row.get("entry"));
            AddressSet before = manualBoundaryBody(row.get("before"), entry, false);
            AddressSet body = manualBoundaryBody(row.get("body"), entry, true);
            Function original = manager.getFunctionAt(entry);
            if ((before == null) != (original == null) || (original != null &&
                    (original.isExternal() || original.isThunk() || !original.getBody().hasSameAddresses(before)))) {
                throw new IllegalArgumentException("Unedited function body differs at " + address(entry));
            }
            if (edits.putIfAbsent(entry, new BodyEdit(entry, original, body)) != null || Objects.equals(before, body)) {
                throw new IllegalArgumentException("Duplicate or unchanged function edit at " + address(entry));
            }
            if (body != null) {
                if (proposed.intersects(body)) throw new IllegalArgumentException("Proposed function bodies overlap");
                proposed.add(body);
            }
        }
        var owners = manager.getFunctionsOverlapping(proposed);
        while (owners.hasNext()) {
            monitor.checkCancelled();
            Address owner = owners.next().getEntryPoint();
            if (!edits.containsKey(owner)) {
                throw new IllegalArgumentException("Proposed body overlaps unedited function at " + address(owner));
            }
        }
        int transaction = currentProgram.startTransaction("Macscope accepted manual function boundaries");
        boolean applied = false;
        try {
            for (BodyEdit edit : edits.values()) {
                monitor.checkCancelled();
                if (edit.original() == null) continue;
                if (edit.body() == null) {
                    if (!manager.removeFunction(edit.entry())) throw new IllegalStateException("Could not remove edited function");
                } else {
                    // Release all old ranges before assigning any replacement body.
                    edit.original().setBody(new AddressSet(edit.entry(), edit.entry()));
                }
            }
            for (BodyEdit edit : edits.values()) {
                monitor.checkCancelled();
                if (edit.body() == null) continue;
                if (edit.original() == null) {
                    manager.createFunction(null, edit.entry(), edit.body(), SourceType.USER_DEFINED);
                } else {
                    edit.original().setBody(edit.body());
                }
            }
            for (BodyEdit edit : edits.values()) {
                Function observed = manager.getFunctionAt(edit.entry());
                if ((observed == null) != (edit.body() == null) ||
                        (observed != null && !observed.getBody().hasSameAddresses(edit.body()))) {
                    throw new IllegalStateException("Applied function body differs at " + address(edit.entry()));
                }
            }
            applied = true;
        } finally {
            currentProgram.endTransaction(transaction, applied);
        }
        enableHeadlessAnalysis(false);
        root.addProperty("function_count_total_reported_by_engine", manager.getFunctionCount());
        JsonObject report = new JsonObject();
        put(report, "policy", MANUAL_BOUNDARY_POLICY);
        put(report, "request_sha256", HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(content)));
        report.addProperty("annotation_revision", revision);
        report.add("edits", rows);
        root.add("manual_boundaries", report);
    }

    Address manualBoundaryAddress(JsonElement value) throws AddressFormatException {
        String text = value.getAsString();
        if (!text.matches("0x(?:0|[1-9a-f][0-9a-f]{0,15})")) {
            throw new IllegalArgumentException("Invalid manual boundary address");
        }
        return currentProgram.getAddressFactory().getDefaultAddressSpace().getAddress(text.substring(2));
    }

    AddressSet manualBoundaryBody(JsonElement value, Address entry, boolean requireDecoded) throws Exception {
        if (value.isJsonNull()) return null;
        JsonArray ranges = value.getAsJsonArray();
        if (ranges.size() < 1 || ranges.size() > 16) throw new IllegalArgumentException("Invalid function range count");
        AddressSet body = new AddressSet();
        for (JsonElement element : ranges) {
            monitor.checkCancelled();
            JsonArray range = element.getAsJsonArray();
            if (range.size() != 2) throw new IllegalArgumentException("Invalid function range");
            Address lo = manualBoundaryAddress(range.get(0)), hi = manualBoundaryAddress(range.get(1));
            if (lo.compareTo(hi) > 0 || Long.compareUnsigned(hi.subtract(lo), MAX_BOUNDARY_BYTES) >= 0) {
                throw new IllegalArgumentException("Invalid or oversized function range");
            }
            body.addRange(lo, hi);
        }
        if (!body.contains(entry) || body.getNumAddressRanges() != ranges.size() ||
                body.getNumAddresses() > MAX_BOUNDARY_BYTES) {
            throw new IllegalArgumentException("Function body must contain its entry and use distinct ranges within 64 KiB");
        }
        if (requireDecoded) {
            if (currentProgram.getListing().getInstructionAt(entry) == null) {
                throw new IllegalArgumentException("Function entry is not a decoded instruction at " + address(entry));
            }
            for (AddressRange range : body) {
                Address lo = range.getMinAddress(), hi = range.getMaxAddress();
                if (!decodedExtent(lo, hi)) {
                    throw new IllegalArgumentException("Function body is not complete executable instructions at " + address(lo));
                }
            }
        }
        return body;
    }

    boolean decodedExtent(Address lo, Address hi) throws Exception {
        MemoryBlock block = currentProgram.getMemory().getBlock(lo);
        if (block == null || !block.isExecute() || !block.contains(hi)) return false;
        InstructionIterator instructions = currentProgram.getListing().getInstructions(new AddressSet(lo, hi), true);
        Address next = lo, last = null;
        while (instructions.hasNext()) {
            monitor.checkCancelled();
            Instruction instruction = instructions.next();
            if (!instruction.getAddress().equals(next)) return false;
            last = instruction.getMaxAddress();
            next = last.next();
        }
        return hi.equals(last);
    }

    String joinBoundary(FunctionManager manager, BoundaryCandidate candidate) throws Exception {
        Function owner = candidate.owner(), competing = candidate.competing();
        if (candidate.nextStart() == null) return "unbounded_linker_extent";
        if (competing.getSymbol().getSource() != SourceType.DEFAULT) return "named_competing_entry";
        AddressSet body = new AddressSet(owner.getBody());
        body.add(competing.getBody());
        if (body.getNumAddressRanges() != 1 || !body.getMinAddress().equals(owner.getEntryPoint()) ||
            body.getMaxAddress().compareTo(candidate.nextStart()) >= 0 || body.getNumAddresses() > MAX_BOUNDARY_BYTES) {
            return "noncontiguous_or_oversized_body";
        }
        if (!decodedExtent(body.getMinAddress(), body.getMaxAddress())) return "unconfirmed_instruction_extent";
        var references = currentProgram.getReferenceManager();
        AddressIterator targets = references.getReferenceDestinationIterator(competing.getBody(), true);
        int visited = 0;
        while (targets.hasNext()) {
            ReferenceIterator refs = references.getReferencesTo(targets.next());
            while (refs.hasNext()) {
                monitor.checkCancelled();
                if (++visited > MAX_BOUNDARY_REFERENCES) return "reference_limit";
                if (!body.contains(refs.next().getFromAddress())) return "outside_reference";
            }
        }
        int transaction = currentProgram.startTransaction("Macscope linker-confirmed fallthrough join");
        boolean joined = false;
        try {
            if (!manager.removeFunction(competing.getEntryPoint())) {
                throw new IllegalStateException("Could not remove the competing function");
            }
            owner.setBody(body);
            joined = true;
            return "joined";
        }
        finally {
            currentProgram.endTransaction(transaction, joined);
        }
    }

    void sections() {
        JsonArray out = new JsonArray();
        String err = null;
        boolean truncated = false;
        int total = 0;
        try {
            MemoryBlock[] blocks = currentProgram.getMemory().getBlocks();
            total = blocks.length;
            for (int i = 0; i < blocks.length && i < MAX_SECTIONS; i++) {
                monitor.checkCancelled();
                MemoryBlock b = blocks[i];
                JsonObject item = new JsonObject();
                put(item, "name", b.getName()); put(item, "start", address(b.getStart()));
                put(item, "end", address(b.getEnd())); item.addProperty("size", b.getSize());
                item.addProperty("r", b.isRead()); item.addProperty("w", b.isWrite());
                item.addProperty("x", b.isExecute()); item.addProperty("loaded", b.isLoaded());
                item.addProperty("initialized", b.isInitialized());
                put(item, "source", b.getSourceName()); put(item, "type", b.getType().toString());
                JsonArray sources = new JsonArray();
                List<MemoryBlockSourceInfo> infos = b.getSourceInfos();
                int sourceLimit = Math.min(infos.size(), 64);
                for (int j = 0; j < sourceLimit; j++) {
                    MemoryBlockSourceInfo si = infos.get(j);
                    JsonObject source = new JsonObject();
                    put(source, "start", address(si.getMinAddress())); put(source, "end", address(si.getMaxAddress()));
                    var file = si.getFileBytes();
                    if (file.isEmpty()) {
                        source.add("file_offset", JsonNull.INSTANCE);
                    } else if (mode.equals("import")) {
                        long offset = si.getFileBytesOffset();
                        if (offset < 0) source.add("file_offset", JsonNull.INSTANCE);
                        else {
                            put(source, "file_name", file.get().getFilename());
                            source.addProperty("file_offset", Math.addExact(file.get().getFileOffset(), offset));
                        }
                    } else source.addProperty("file_offset", si.getFileBytesOffset());
                    sources.add(source);
                }
                item.add("sources", sources);
                item.addProperty("sources_truncated", infos.size() > sourceLimit);
                if (infos.size() > sourceLimit) partial = true;
                if (!append(out, item, true)) { truncated = true; break; }
            }
            truncated |= out.size() < total;
        } catch (Exception e) { err = error(e); }
        root.add("sections", out);
        coverage.add("sections", facet(out.size(), total, truncated, err, "complete"));
    }

    void symbols() {
        JsonArray out = new JsonArray(); String err = null; boolean trunc = false;
        try {
            SymbolIterator it = currentProgram.getSymbolTable().getAllSymbols(true);
            while (out.size() < MAX_SYMBOLS && it.hasNext()) {
                monitor.checkCancelled();
                if (!append(out, symbol(it.next()), true)) { trunc = true; break; }
            }
            trunc |= it.hasNext();
        } catch (Exception e) { err = error(e); }
        root.add("symbols", out);
        coverage.add("symbols", facet(out.size(), -1, trunc, err, "complete"));
    }

    JsonObject symbol(Symbol s) {
        JsonObject item = new JsonObject();
        put(item, "name", s.getName()); put(item, "address", address(s.getAddress()));
        put(item, "namespace", s.getParentNamespace().getName(true));
        put(item, "type", s.getSymbolType().toString()); put(item, "source", s.getSource().toString());
        item.addProperty("is_external", s.isExternal()); item.addProperty("is_primary", s.isPrimary());
        return item;
    }

    void imports() {
        JsonArray out = new JsonArray(); String err = null; boolean trunc = false;
        try {
            SymbolIterator it = currentProgram.getSymbolTable().getExternalSymbols();
            while (out.size() < MAX_SYMBOLS && it.hasNext()) {
                monitor.checkCancelled(); Symbol s = it.next(); JsonObject item = symbol(s);
                ExternalLocation location = currentProgram.getExternalManager().getExternalLocation(s);
                put(item, "library", location == null ? null : location.getLibraryName());
                if (!append(out, item, true)) { trunc = true; break; }
            }
            trunc |= it.hasNext();
        } catch (Exception e) { err = error(e); }
        root.add("imports", out);
        coverage.add("imports", facet(out.size(), -1, trunc, err, "complete"));
    }

    void exports() {
        JsonArray out = new JsonArray(); String err = null; boolean trunc = false;
        try {
            SymbolTable table = currentProgram.getSymbolTable();
            AddressIterator it = table.getExternalEntryPointIterator();
            while (out.size() < MAX_SYMBOLS && it.hasNext()) {
                monitor.checkCancelled(); Address a = it.next(); Symbol s = table.getPrimarySymbol(a);
                JsonObject item = s == null ? new JsonObject() : symbol(s);
                put(item, "address", address(a));
                if (!append(out, item, true)) { trunc = true; break; }
            }
            trunc |= it.hasNext();
        } catch (Exception e) { err = error(e); }
        root.add("exports", out);
        coverage.add("exports", facet(out.size(), -1, trunc, err, "complete"));
    }

    void strings() {
        JsonArray out = new JsonArray(); String err = null; boolean trunc = false; int scanned = 0;
        try {
            MessageDigest bytesDigest = MessageDigest.getInstance("SHA-256");
            DataIterator it = currentProgram.getListing().getDefinedData(true);
            while (scanned < MAX_SCAN && out.size() < MAX_STRINGS && it.hasNext()) {
                monitor.checkCancelled(); Data data = it.next(); scanned++;
                if (!data.hasStringValue()) continue;
                JsonObject item = new JsonObject(); put(item, "address", address(data.getAddress()));
                item.addProperty("length_bytes", data.getLength());
                boolean oversized = data.getLength() > MAX_TEXT * 4;
                Object value = oversized ? null : data.getValue();
                String str = value == null ? null : value.toString();
                if (str != null && str.length() <= MAX_TEXT) {
                    str = verifyStringEncoding(data, item, str, bytesDigest);
                }
                put(item, "value", str);
                item.addProperty("value_truncated", oversized || (str != null && str.length() > MAX_TEXT));
                if (oversized) partial = true;
                put(item, "data_type", data.getDataType().getName());
                if (!append(out, item, true)) { trunc = true; break; }
            }
            trunc |= it.hasNext();
        } catch (Exception e) { err = error(e); }
        root.add("strings", out);
        JsonObject cov = facet(out.size(), -1, trunc, err, "complete");
        cov.addProperty("defined_data_scanned", scanned); cov.addProperty("scan_limit", MAX_SCAN);
        put(cov, "scope", "Ghidra-defined string data, not an exhaustive raw-byte scan"); coverage.add("strings", cov);
    }

    String verifyStringEncoding(Data data, JsonObject item, String value, MessageDigest bytesDigest) {
        StringDataInstance instance = StringDataInstance.getStringDataInstance(data);
        if (instance == StringDataInstance.NULL_INSTANCE) return value;
        String charset = instance.getCharsetName();
        put(item, "engine_charset", charset);
        try {
            byte[] bytes = data.getBytes();
            if (bytes.length != data.getLength() || bytes.length == 0) return value;
            Charset decoder;
            String encoding;
            String evidence = "ghidra_charset_and_bytes";
            int offset = 0;
            if ("US-ASCII".equals(charset) || "UTF-8".equals(charset)) {
                decoder = "US-ASCII".equals(charset) ? StandardCharsets.US_ASCII : StandardCharsets.UTF_8;
                encoding = "US-ASCII".equals(charset) ? "ascii" : "utf8";
                if (decoder == StandardCharsets.US_ASCII &&
                    data.getBaseDataType() instanceof TerminatedStringDataType &&
                    !StandardCharsets.US_ASCII.newEncoder().canEncode(value) &&
                    withoutTrailingNulls(new String(bytes, StandardCharsets.US_ASCII)).equals(value)) {
                    // The Mach-O loader also uses this ASCII datatype for UTF-8 C strings.
                    decoder = StandardCharsets.UTF_8;
                    encoding = "utf8";
                    evidence = "strict_utf8_c_string_bytes";
                }
            } else if ("UTF-16".equals(charset) || "UTF-16LE".equals(charset)) {
                if ("UTF-16".equals(charset) && bytes.length >= 2) {
                    int bom = (Byte.toUnsignedInt(bytes[0]) << 8) | Byte.toUnsignedInt(bytes[1]);
                    if (bom == 0xfeff || (bom != 0xfffe &&
                        EndianSettingsDefinition.DEF.isBigEndian(data, data))) return value;
                    if (bom == 0xfffe) offset = 2;
                }
                decoder = StandardCharsets.UTF_16LE;
                encoding = "utf16le";
            } else {
                return value;
            }
            String decoded = decoder.newDecoder().decode(ByteBuffer.wrap(bytes, offset, bytes.length - offset)).toString();
            if (evidence.equals("strict_utf8_c_string_bytes")) {
                decoded = withoutTrailingNulls(decoded);
            } else if (!decoded.equals(value) && !withoutTrailingNulls(decoded).equals(value)) {
                return value;
            } else {
                decoded = value;
            }
            put(item, "encoding", encoding);
            put(item, "encoding_evidence", evidence);
            put(item, "bytes_sha256", HexFormat.of().formatHex(bytesDigest.digest(bytes)));
            return decoded;
        } catch (CharacterCodingException | MemoryAccessException e) {
            return value;
        }
    }

    String withoutTrailingNulls(String value) {
        int end = value.length();
        while (end > 0 && value.charAt(end - 1) == 0) end--;
        return value.substring(0, end);
    }

    void functions(int limit, int timeout, String entry, boolean fromImport) {
        JsonArray out = root.getAsJsonArray("functions");
        DecompInterface decomp = new DecompInterface();
        String err = null; boolean trunc = false; int visited = 0;
        try {
            DecompileOptions opts = new DecompileOptions();
            opts.setDefaultTimeout(timeout); opts.setMaxInstructions(100000);
            opts.setMaxJumpTableEntries(4096); opts.setMaxPayloadMBytes(8);
            decomp.setOptions(opts); decomp.toggleCCode(true);
            // Markup tokens resolve their machine addresses through syntax-tree p-code ops.
            decomp.toggleSyntaxTree(true);
            boolean opened = false;
            long openStarted = System.nanoTime();
            try {
                opened = decomp.openProgram(currentProgram);
            } finally {
                JsonObject timing = new JsonObject();
                timing.addProperty("elapsed_ns", System.nanoTime() - openStarted);
                timing.addProperty("opened", opened);
                decompilerTiming.add("open_program", timing);
            }
            if (!opened) { decompilerError = clipped(decomp.getLastMessage(), MAX_TEXT); partial = true; }
            if (entry == null) {
                BasicBlockModel model = new BasicBlockModel(currentProgram);
                FunctionIterator it = currentProgram.getFunctionManager().getFunctions(true);
                FunctionIterator external = currentProgram.getFunctionManager().getExternalFunctions();
                while (visited < limit && (it.hasNext() || external.hasNext())) {
                    monitor.checkCancelled();
                    Function f = it.hasNext() ? it.next() : external.next(); visited++;
                    JsonObject item = function(f, model, opened ? decomp : null, timeout);
                    if (!append(out, item, false)) { trunc = true; break; }
                }
                trunc |= it.hasNext() || external.hasNext();
            } else {
                Function f = functionAt(entry);
                monitor.checkCancelled();
                JsonObject item;
                if (fromImport) {
                    item = function(f, new BasicBlockModel(currentProgram), opened ? decomp : null, timeout);
                } else {
                    item = new JsonObject();
                    JsonObject facets = new JsonObject();
                    item.add("coverage", facets);
                    put(item, "entry_va", address(f.getEntryPoint()));
                    decompile(f, opened ? decomp : null, timeout, item, facets);
                }
                visited = 1;
                trunc = !append(out, item, false);
            }
        } catch (Exception e) { err = error(e); }
        finally {
            try { decomp.dispose(); }
            catch (Exception e) {
                String cleanup = "Decompiler disposal failed: " + error(e);
                err = err == null ? cleanup : clipped(err + "; " + cleanup, MAX_TEXT);
            }
        }
        root.addProperty("function_count_enumerated", out.size());
        root.addProperty("functions_truncated", trunc);
        root.addProperty("function_count_attempted", visited);
        int total = entry == null ? currentProgram.getFunctionManager().getFunctionCount() : 1;
        coverage.add("functions", facet(out.size(), total, trunc, err, "complete"));
    }

    Function functionAt(String entry) throws AddressFormatException {
        if (!entry.matches("0x[0-9a-f]{1,16}")) throw new IllegalArgumentException("Invalid RAM function entry");
        Address location = currentProgram.getAddressFactory().getDefaultAddressSpace().getAddress(entry.substring(2));
        Function function = currentProgram.getFunctionManager().getFunctionAt(location);
        if (function == null) throw new IllegalStateException("Selected entry is absent from saved Program");
        return function;
    }

    void hintedDecompile(int timeout, String entry, Path path) throws Exception {
        byte[] content;
        try (InputStream input = Files.newInputStream(path, LinkOption.NOFOLLOW_LINKS)) {
            content = input.readNBytes(65537);
        }
        if (content.length > 65536) throw new IllegalArgumentException("Type hint request exceeds its bound");
        JsonObject request = JsonParser.parseString(new String(content, StandardCharsets.UTF_8)).getAsJsonObject();
        JsonArray hints = request.getAsJsonArray("hints");
        if (!"macscope-type-hints/2".equals(request.get("schema").getAsString()) ||
            hints.size() < 1 || hints.size() > 128) {
            throw new IllegalArgumentException("Invalid type hint request");
        }
        int transaction = currentProgram.startTransaction("Macscope temporary type hints");
        try {
            JsonArray applied = new JsonArray();
            Map<String, HintStructure> structures = new TreeMap<>();
            for (JsonElement element : hints) {
                monitor.checkCancelled();
                JsonObject hint = element.getAsJsonObject();
                Function function = functionAt(hint.get("entry_va").getAsString());
                if (function.isExternal() || function.isThunk()) throw new IllegalArgumentException("Invalid type hint function");
                JsonObject row = hint.deepCopy();
                if (hint.keySet().equals(Set.of("entry_va", "revision", "return_type"))) {
                    DataType type = hintType(hint.get("return_type").getAsString(), structures);
                    if (type instanceof StructureDataType && function.hasCustomVariableStorage()) {
                        throw new IllegalArgumentException("Aggregate returns require dynamic storage");
                    }
                    put(row, "previous_type", function.getReturnType().getDisplayName());
                    function.setReturnType(type, SourceType.USER_DEFINED);
                    if (!function.getReturn().getFormalDataType().isEquivalent(type)) {
                        throw new IllegalStateException("Accepted return type was not applied");
                    }
                    put(row, "resolved_type", function.getReturnType().getDisplayName());
                } else if (hint.keySet().equals(Set.of("entry_va", "revision", "parameter_types"))) {
                    applyParameterHint(function, hint.getAsJsonArray("parameter_types"), row, structures);
                } else {
                    throw new IllegalArgumentException("Invalid type hint fields");
                }
                applied.add(row);
            }
            root.add("applied_type_hints", applied);
            if (!structures.isEmpty()) {
                JsonArray layouts = new JsonArray();
                for (HintStructure structure : structures.values()) layouts.add(structure.layout());
                root.add("aggregate_type_layouts", layouts);
            }
            functions(1, timeout, entry, false);
        } finally {
            currentProgram.endTransaction(transaction, false);
        }
    }

    void applyParameterHint(Function function, JsonArray names, JsonObject row,
            Map<String, HintStructure> structures) throws Exception {
        if (names.size() > 16 || function.hasCustomVariableStorage()) {
            throw new IllegalArgumentException("Parameter hints require at most 16 types and dynamic storage");
        }
        List<ParameterImpl> parameters = new ArrayList<>();
        for (JsonElement name : names) {
            String requested = name.getAsString();
            if ("void".equals(requested)) throw new IllegalArgumentException("A formal parameter cannot have type void");
            parameters.add(new ParameterImpl(null, hintType(requested, structures), currentProgram, SourceType.USER_DEFINED));
        }
        String convention = function.getCallingConventionName();
        boolean variadic = function.hasVarArgs();
        DataType returnType = function.getReturn().getFormalDataType();
        row.add("previous_parameter_types", typeNames(formalTypes(function)));
        function.replaceParameters(parameters, Function.FunctionUpdateType.DYNAMIC_STORAGE_FORMAL_PARAMS,
            true, SourceType.USER_DEFINED);
        List<DataType> applied = formalTypes(function);
        if (applied.size() != parameters.size() || !Objects.equals(convention, function.getCallingConventionName()) ||
            variadic != function.hasVarArgs() || !function.getReturn().getFormalDataType().isEquivalent(returnType)) {
            throw new IllegalStateException("Accepted parameter list changed the return type or calling convention");
        }
        for (int i = 0; i < applied.size(); i++) {
            if (!applied.get(i).isEquivalent(parameters.get(i).getFormalDataType())) {
                throw new IllegalStateException("Accepted formal parameter type was not applied");
            }
        }
        row.add("resolved_parameter_types", typeNames(applied));
        put(row, "calling_convention", convention);
        row.addProperty("variadic", variadic);
    }

    List<DataType> formalTypes(Function function) {
        List<DataType> types = new ArrayList<>();
        for (Parameter parameter : function.getParameters()) {
            if (!parameter.isAutoParameter()) types.add(parameter.getFormalDataType());
        }
        return types;
    }

    JsonArray typeNames(List<DataType> types) {
        JsonArray names = new JsonArray();
        for (DataType type : types) names.add(type.getDisplayName());
        return names;
    }

    record HintStructure(String definition, StructureDataType type) {
        JsonObject layout() {
            JsonObject layout = new JsonObject();
            layout.addProperty("definition", definition);
            layout.addProperty("name", type.getName());
            layout.addProperty("size_bytes", type.getLength());
            layout.addProperty("alignment_bytes", type.getAlignment());
            JsonArray fields = new JsonArray();
            for (var component : type.getDefinedComponents()) {
                JsonObject field = new JsonObject();
                field.addProperty("name", component.getFieldName());
                field.addProperty("type", component.getDataType().getDisplayName());
                field.addProperty("offset_bytes", component.getOffset());
                field.addProperty("size_bytes", component.getLength());
                fields.add(field);
            }
            layout.add("fields", fields);
            return layout;
        }
    }

    DataType hintType(String name, Map<String, HintStructure> structures) {
        if (name.length() > 512) throw new IllegalArgumentException("Hint type exceeds its bound");
        var matcher = HINT_STRUCT.matcher(name);
        if (!matcher.matches()) return scalarHintType(name);
        String definition = matcher.group(1), typeName = matcher.group(2);
        HintStructure structure = structures.get(typeName);
        if (structure == null) {
            var manager = currentProgram.getDataTypeManager();
            var type = new StructureDataType(new CategoryPath("/macscope/type-hints"), typeName, 0, manager);
            type.setPackingEnabled(true);
            String[] fields = matcher.group(3).split(";", -1);
            if (fields.length > 16) throw new IllegalArgumentException("Too many structure fields");
            Set<String> seen = new TreeSet<>();
            for (String field : fields) {
                var member = HINT_FIELD.matcher(field);
                if (!member.matches() || !seen.add(member.group(1)) || "void".equals(member.group(2))) {
                    throw new IllegalArgumentException("Invalid named structure field");
                }
                type.add(scalarHintType(member.group(2)), member.group(1), null);
            }
            structure = new HintStructure(definition, type);
            structures.put(typeName, structure);
        } else if (!structure.definition().equals(definition)) {
            throw new IllegalArgumentException("Conflicting structure definitions");
        }
        return hintPointers(structure.type(), matcher.group(4).length());
    }

    DataType scalarHintType(String name) {
        if (!name.matches("(void|bool|float|double|u?int(8|16|32|64)_t)\\*{0,2}")) {
            throw new IllegalArgumentException("Unsupported hint type");
        }
        int pointer = name.indexOf('*');
        String base = pointer < 0 ? name : name.substring(0, pointer);
        var manager = currentProgram.getDataTypeManager();
        DataType type;
        if (base.equals("void")) {
            type = VoidDataType.dataType;
        } else if (base.equals("bool")) {
            type = BooleanDataType.dataType;
        } else if (base.equals("float") || base.equals("double")) {
            type = AbstractFloatDataType.getFloatDataType(base.equals("float") ? 4 : 8, manager);
        } else {
            boolean unsigned = base.startsWith("u");
            int bytes = Integer.parseInt(base.substring(unsigned ? 4 : 3, base.length()-2))/8;
            type = unsigned ? AbstractIntegerDataType.getUnsignedDataType(bytes, manager)
                : AbstractIntegerDataType.getSignedDataType(bytes, manager);
        }
        return hintPointers(type, name.length() - base.length());
    }

    DataType hintPointers(DataType type, int count) {
        for (int i = 0; i < count; i++) {
            type = new PointerDataType(type, currentProgram.getDataTypeManager());
        }
        return type;
    }

    void entryLabels(Function f, JsonObject item, JsonObject cov) {
        JsonArray labels = new JsonArray();
        String err = null;
        boolean truncated = false;
        try {
            SymbolIterator symbols = currentProgram.getSymbolTable().getSymbolsAsIterator(f.getEntryPoint());
            int scanned = 0;
            while (scanned < MAX_ENTRY_SYMBOLS && symbols.hasNext()) {
                monitor.checkCancelled();
                Symbol s = symbols.next();
                scanned++;
                if (s.getSymbolType() != SymbolType.LABEL) continue;
                String name = s.getName(), namespace = s.getParentNamespace().getName(true);
                if (name.length() > MAX_TEXT || namespace.length() > MAX_TEXT) {
                    truncated = true;
                    continue;
                }
                JsonObject row = new JsonObject();
                put(row, "name", name); put(row, "namespace", namespace);
                put(row, "source", s.getSource().toString());
                labels.add(row);
            }
            truncated |= symbols.hasNext();
        } catch (Exception e) { err = error(e); }
        item.add("entry_labels", labels);
        cov.add("entry_labels", facet(labels.size(), truncated || err != null ? -1 : labels.size(),
                                     truncated, err, "complete"));
    }

    void thunkTarget(Function f, JsonObject item, JsonObject cov) {
        String err = null;
        JsonObject target = null;
        try {
            Function next = f.getThunkedFunction(false);
            if (next == null) throw new IllegalStateException("Thunk target is unavailable");
            JsonObject row = new JsonObject();
            put(row, "engine_entry", address(next.getEntryPoint()));
            put(row, "name", next.getName());
            put(row, "namespace", next.getParentNamespace().getName(true));
            row.addProperty("is_external", next.isExternal());
            if (next.isExternal()) {
                ExternalLocation external = next.getExternalLocation();
                if (external != null) {
                    put(row, "library", external.getLibraryName());
                    put(row, "imported_name", external.getOriginalImportedName());
                }
            }
            target = row;
        } catch (Exception e) { err = error(e); }
        item.add("thunk_target", target == null ? JsonNull.INSTANCE : target);
        cov.add("thunk_target", facet(target == null ? 0 : 1, 1, false, err, "complete"));
    }

    JsonObject function(Function f, BasicBlockModel model, DecompInterface decomp, int timeout) {
        JsonObject item = new JsonObject(), cov = new JsonObject();
        item.add("coverage", cov); put(item, "name", f.getName());
        put(item, "namespace", f.getParentNamespace().getName(true)); put(item, "entry_va", address(f.getEntryPoint()));
        item.addProperty("is_external", f.isExternal()); item.addProperty("is_thunk", f.isThunk());
        entryLabels(f, item, cov);
        if (f.isThunk()) thunkTarget(f, item, cov);
        try { put(item, "signature", f.getSignature(false).toString()); put(item, "calling_convention", f.getCallingConventionName()); }
        catch (Exception e) { put(item, "signature", null); put(item, "signature_error", error(e)); partial = true; }
        JsonArray ranges = new JsonArray(); String err = null; boolean trunc = false;
        try {
            AddressRangeIterator it = f.getBody().getAddressRanges(true);
            while (ranges.size() < MAX_RANGES && it.hasNext()) {
                monitor.checkCancelled(); AddressRange r = it.next(); JsonArray pair = new JsonArray();
                pair.add(address(r.getMinAddress())); pair.add(address(r.getMaxAddress())); ranges.add(pair);
            }
            trunc = it.hasNext();
        } catch (Exception e) { err = error(e); }
        item.add("body_ranges", ranges); cov.add("body_ranges", facet(ranges.size(), -1, trunc, err, "complete"));
        instructions(f, item, cov); cfg(f, model, item, cov); xrefs(f, item, cov);
        decompile(f, decomp, timeout, item, cov);
        return item;
    }

    void instructions(Function f, JsonObject item, JsonObject cov) {
        JsonArray out = new JsonArray(); String err = null; boolean trunc = false;
        try {
            InstructionIterator it = currentProgram.getListing().getInstructions(f.getBody(), true);
            while (out.size() < MAX_INSTRUCTIONS && it.hasNext()) {
                monitor.checkCancelled(); Instruction ins = it.next(); JsonObject row = new JsonObject();
                put(row, "addr", address(ins.getAddress())); put(row, "bytes", hex(ins.getBytes()));
                put(row, "text", ins.toString()); put(row, "flow", ins.getFlowType().toString());
                put(row, "fallthrough", address(ins.getFallThrough())); out.add(row);
            }
            trunc = it.hasNext();
        } catch (Exception e) { err = error(e); }
        item.add("instructions", out); item.addProperty("instruction_count", out.size());
        item.addProperty("instructions_truncated", trunc); put(item, "instructions_error", err);
        cov.add("instructions", facet(out.size(), -1, trunc, err, "complete"));
    }

    void cfg(Function f, BasicBlockModel model, JsonObject item, JsonObject cov) {
        JsonArray out = new JsonArray(); String err = null; boolean trunc = false, edgesTrunc = false; int edges = 0;
        try {
            CodeBlockIterator it = model.getCodeBlocksContaining(f.getBody(), monitor);
            while (out.size() < MAX_BLOCKS && it.hasNext()) {
                monitor.checkCancelled(); CodeBlock b = it.next(); JsonObject row = new JsonObject();
                put(row, "min", address(b.getMinAddress())); put(row, "max", address(b.getMaxAddress()));
                put(row, "flow", b.getFlowType().toString()); JsonArray dsts = new JsonArray();
                CodeBlockReferenceIterator refs = b.getDestinations(monitor);
                while (edges < MAX_EDGES && refs.hasNext()) {
                    monitor.checkCancelled(); CodeBlockReference ref = refs.next(); JsonObject edge = new JsonObject();
                    put(edge, "from", address(ref.getReferent())); put(edge, "to", address(ref.getDestinationAddress()));
                    put(edge, "flow", ref.getFlowType().toString()); dsts.add(edge); edges++;
                }
                boolean omitted = refs.hasNext(); edgesTrunc |= omitted;
                row.add("dsts", dsts); row.addProperty("edges_truncated", omitted); out.add(row);
            }
            trunc = it.hasNext();
        } catch (Exception e) { err = error(e); }
        item.add("blocks", out); item.addProperty("block_count", out.size()); item.addProperty("edge_count", edges);
        item.addProperty("blocks_truncated", trunc); item.addProperty("edges_truncated", edgesTrunc);
        put(item, "cfg_error", err); cov.add("cfg", facet(out.size(), -1, trunc || edgesTrunc, err, "complete"));
    }

    void xrefs(Function f, JsonObject item, JsonObject cov) {
        JsonArray to = new JsonArray(), from = new JsonArray(); String toError = null, fromError = null;
        boolean toTrunc = false, fromTrunc = false; int scanned = 0;
        try {
            ReferenceIterator it = currentProgram.getReferenceManager().getReferencesTo(f.getEntryPoint());
            while (to.size() < MAX_XREFS && it.hasNext()) { monitor.checkCancelled(); to.add(reference(it.next())); }
            toTrunc = it.hasNext();
        } catch (Exception e) { toError = error(e); }
        try {
            AddressIterator sources = currentProgram.getReferenceManager().getReferenceSourceIterator(f.getBody(), true);
            while (scanned < MAX_INSTRUCTIONS && from.size() < MAX_XREFS && sources.hasNext()) {
                monitor.checkCancelled(); Address a = sources.next(); scanned++;
                ReferenceIterator refs = currentProgram.getReferenceManager().getReferenceIterator(a);
                while (from.size() < MAX_XREFS && refs.hasNext()) {
                    monitor.checkCancelled(); Reference r = refs.next();
                    if (!r.getFromAddress().equals(a)) break;
                    from.add(reference(r));
                }
                if (from.size() == MAX_XREFS && refs.hasNext()) {
                    Reference next = refs.next();
                    if (next.getFromAddress().equals(a)) fromTrunc = true;
                }
            }
            fromTrunc |= sources.hasNext();
        } catch (Exception e) { fromError = error(e); }
        item.add("xrefs_to_entry", to); item.addProperty("xrefs_to_entry_count", to.size());
        item.addProperty("xrefs_to_entry_truncated", toTrunc); put(item, "xrefs_to_entry_error", toError);
        item.add("xrefs_from_sample", from); item.addProperty("xrefs_from_sampled", from.size());
        if (!fromTrunc && fromError == null) item.addProperty("xrefs_from_total", from.size());
        else item.add("xrefs_from_total", JsonNull.INSTANCE);
        item.addProperty("xrefs_from_truncated", fromTrunc); put(item, "xrefs_from_error", fromError);
        cov.add("xrefs_to_entry", facet(to.size(), -1, toTrunc, toError, "complete"));
        JsonObject fcov = facet(from.size(), -1, fromTrunc, fromError, "complete");
        fcov.addProperty("source_addresses_scanned", scanned); cov.add("xrefs_from", fcov);
    }

    JsonObject reference(Reference r) {
        JsonObject result = new JsonObject(); put(result, "from", address(r.getFromAddress()));
        put(result, "to", address(r.getToAddress())); put(result, "type", r.getReferenceType().toString());
        put(result, "source", r.getSource().toString()); result.addProperty("operand_index", r.getOperandIndex());
        result.addProperty("is_primary", r.isPrimary()); result.addProperty("is_external", r.isExternalReference());
        result.addProperty("from_external", r.getFromAddress().isExternalAddress()); return result;
    }

    void imageReferences() {
        JsonArray references = new JsonArray(), computed = new JsonArray();
        String refError = null, instructionError = null;
        boolean refTruncated = false, instructionTruncated = false;
        int sourcesSeen = 0, sourcesTotal = -1;
        try {
            var manager = currentProgram.getReferenceManager();
            sourcesTotal = manager.getReferenceSourceCount();
            // Ghidra stores external entry points under a special source outside the forward iterator.
            AddressIterator entries = currentProgram.getSymbolTable().getExternalEntryPointIterator();
            while (references.size() < MAX_IMAGE_REFS && entries.hasNext()) {
                monitor.checkCancelled();
                Reference entry = manager.getReference(Address.EXT_FROM_ADDRESS, entries.next(), CodeUnit.MNEMONIC);
                if (entry == null || !entry.isEntryPointReference() || !append(references, reference(entry), false)) {
                    refTruncated = true;
                    break;
                }
                sourcesSeen = 1;
            }
            refTruncated |= entries.hasNext();
            Address start = Address.EXT_FROM_ADDRESS;
            for (var space : currentProgram.getAddressFactory().getAllAddressSpaces()) {
                Address first = space.getMinAddress();
                if (first.compareTo(start) < 0) start = first;
            }
            ReferenceIterator refs = manager.getReferenceIterator(start);
            Address previous = null;
            while (references.size() < MAX_IMAGE_REFS && refs.hasNext()) {
                monitor.checkCancelled();
                Reference ref = refs.next();
                if (ref.isEntryPointReference()) continue;
                if (!append(references, reference(ref), false)) {
                    refTruncated = true;
                    break;
                }
                if (!ref.getFromAddress().equals(previous)) sourcesSeen++;
                previous = ref.getFromAddress();
            }
            refTruncated |= refs.hasNext() || sourcesSeen != sourcesTotal;
        } catch (Exception e) { refError = error(e); }
        int scanned = 0;
        try {
            InstructionIterator it = currentProgram.getListing().getInstructions(true);
            while (scanned < MAX_SCAN && computed.size() < MAX_COMPUTED_SITES && it.hasNext()) {
                monitor.checkCancelled();
                Instruction ins = it.next();
                scanned++;
                var flow = ins.getFlowType();
                if (flow.isComputed() && (flow.isCall() || flow.isJump())) {
                    JsonObject site = new JsonObject();
                    put(site, "addr", address(ins.getAddress()));
                    put(site, "flow", flow.toString());
                    if (!append(computed, site, false)) {
                        instructionTruncated = true;
                        break;
                    }
                }
            }
            instructionTruncated |= it.hasNext();
        } catch (Exception e) { instructionError = error(e); }
        root.add("address_references", references);
        root.add("computed_flow_sites", computed);
        JsonObject refs = facet(references.size(), -1, refTruncated, refError, "complete");
        refs.addProperty("source_addresses_captured", sourcesSeen);
        if (sourcesTotal >= 0) refs.addProperty("source_addresses_total", sourcesTotal);
        coverage.add("address_references", refs);
        JsonObject sites = facet(computed.size(), -1, instructionTruncated, instructionError, "complete");
        sites.addProperty("instructions_scanned", scanned);
        coverage.add("computed_flow_sites", sites);
    }

    void decompile(Function f, DecompInterface decomp, int timeout, JsonObject item, JsonObject cov) {
        String status, err = null, code = null; boolean trunc = false;
        DecompileResults decoded = null;
        if (f.isExternal() || f.isThunk()) {
            status = "not_requested"; notRequested++;
            err = f.isExternal() ? "External function has no body in this image" : "Thunk forwards to another function";
        } else {
            attempted++;
            if (decomp == null) {
                status = "failed"; err = "Decompiler failed to open Program: " + decompilerError; failed++;
            } else {
                try {
                    DecompileResults result;
                    long callStarted = System.nanoTime();
                    try {
                        result = decomp.decompileFunction(f, timeout, monitor);
                    } finally {
                        long elapsed = System.nanoTime() - callStarted;
                        String entry = address(f.getEntryPoint());
                        JsonObject timing = new JsonObject();
                        timing.addProperty("entry", entry != null && entry.length() <= 128 ? entry : null);
                        timing.addProperty("elapsed_ns", elapsed);
                        decompileCalls.add(timing);
                    }
                    if (result == null) { status = "failed"; err = "Native decompiler returned null results"; failed++; }
                    else {
                        err = result.getErrorMessage();
                        if (result.isTimedOut()) { status = "timeout"; timedOut++; }
                        else if (result.isCancelled()) { status = "cancelled"; cancelled++; }
                        else if (result.failedToStart()) { status = "failed"; failed++; }
                        else {
                            DecompiledFunction printed = result.decompileCompleted() ? result.getDecompiledFunction() : null;
                            if (printed == null || printed.getC() == null) {
                                status = "failed"; failed++;
                            } else {
                                status = "complete"; completed++; code = printed.getC(); decoded = result;
                                trunc = code.length() > MAX_PSEUDOCODE;
                                if (trunc) code = clipped(code, MAX_PSEUDOCODE);
                            }
                        }
                    }
                } catch (Exception e) {
                    status = monitor.isCancelled() ? "cancelled" : "failed";
                    if (monitor.isCancelled()) cancelled++; else failed++; err = error(e);
                }
            }
            if (!status.equals("complete")) partial = true;
        }
        put(item, "decompile_status", status); put(item, "decompile_error", err);
        if (code == null) item.add("pseudocode", JsonNull.INSTANCE); else item.addProperty("pseudocode", code);
        item.addProperty("pseudocode_truncated", trunc);
        cov.add("pseudocode", facet(code == null ? 0 : 1, -1, trunc,
            status.equals("not_requested") ? null : err, status));
        if (focusedQuery) nativeScope(f, decoded, item);
        if (decoded != null && !trunc) {
            try {
                if (addressSpans(f, decoded, code, item, cov)) return;
                unavailableSpans(item, cov, "Markup does not align with printed pseudocode");
            } catch (Exception e) {
                unavailableSpans(item, cov, error(e));
            }
        } else {
            unavailableSpans(item, cov, trunc ? "Printed pseudocode is truncated" : "Pseudocode is unavailable");
        }
    }

    void nativeScope(Function function, DecompileResults decoded, JsonObject item) {
        JsonObject scope = new JsonObject();
        scope.addProperty("policy", "macscope-focused-native-scope/1");
        JsonArray outside = new JsonArray();
        java.util.HashSet<String> retained = new java.util.HashSet<>();
        int scanned = 0, outsideOperations = 0;
        boolean truncated = false;
        String err = null;
        try {
            if (decoded == null || decoded.getHighFunction() == null)
                throw new IllegalStateException("Native function unavailable");
            var operations = decoded.getHighFunction().getPcodeOps();
            while (operations.hasNext() && scanned < 100000) {
                monitor.checkCancelled();
                Address target = operations.next().getSeqnum().getTarget();
                scanned++;
                if (target.isMemoryAddress() && !function.getBody().contains(target)) {
                    outsideOperations++;
                    String value = address(target);
                    if (retained.size() < 64 && retained.add(value)) outside.add(value);
                }
            }
            truncated = operations.hasNext();
        } catch (Exception error) { err = error(error); }
        scope.addProperty("operations_scanned", scanned);
        scope.addProperty("operations_truncated", truncated);
        scope.addProperty("outside_body_operations", outsideOperations);
        scope.add("outside_body_addresses", outside);
        put(scope, "error", err);
        scope.addProperty("status", err != null ? "unavailable" : truncated || outsideOperations > 0 ? "partial" : "complete");
        item.add("native_scope", scope);
    }

    void unavailableSpans(JsonObject item, JsonObject cov, String reason) {
        item.add("address_spans", new JsonArray());
        JsonObject coverage = facet(0, -1, false, null, "unavailable");
        coverage.addProperty("reason", reason);
        cov.add("address_spans", coverage);
    }

    boolean addressSpans(Function function, DecompileResults decoded, String code,
                         JsonObject item, JsonObject cov) throws Exception {
        if (decoded.getCCodeMarkup() == null) return false;
        IllegalCharCppTransformer names = new IllegalCharCppTransformer();
        PrettyPrinter printer = new PrettyPrinter(function, decoded.getCCodeMarkup(), names);
        JsonArray spans = new JsonArray();
        int offset = 0, mapped = 0;
        int limit = Math.min(MAX_SPANS_PER_FUNCTION, MAX_SPANS_PER_JOB - retainedSpans);
        for (ClangLine line : printer.getLines()) {
            monitor.checkCancelled();
            String indent = line.getIndentString();
            if (!code.startsWith(indent, offset)) return false;
            offset += indent.length();
            for (ClangToken token : line.getAllTokens()) {
                String tokenText = String.valueOf(token.getText());
                boolean symbol = token instanceof ClangFuncNameToken || token instanceof ClangVariableToken ||
                    token instanceof ClangTypeToken || token instanceof ClangFieldToken || token instanceof ClangLabelToken;
                if (symbol && token.getSyntaxType() != ClangToken.CONST_COLOR) tokenText = names.simplify(tokenText);
                if (!code.startsWith(tokenText, offset)) return false;
                int end = offset + tokenText.length();
                Address lo = token.getMinAddress(), hi = token.getMaxAddress();
                if (offset < end && lo != null && hi != null && lo.isMemoryAddress() &&
                    !lo.getAddressSpace().isOverlaySpace() &&
                    lo.getAddressSpace().equals(hi.getAddressSpace()) && lo.compareTo(hi) <= 0 &&
                    function.getBody().contains(lo, hi)) {
                    mapped++;
                    if (spans.size() < limit) {
                        JsonObject span = new JsonObject();
                        span.addProperty("text_start", offset); span.addProperty("text_end", end);
                        JsonArray ranges = new JsonArray(), range = new JsonArray();
                        range.add(address(lo)); range.add(address(hi)); ranges.add(range);
                        span.add("ranges", ranges); spans.add(span);
                    }
                }
                offset = end;
            }
            if (!code.startsWith(StringUtilities.LINE_SEPARATOR, offset)) return false;
            offset += StringUtilities.LINE_SEPARATOR.length();
        }
        if (offset != code.length()) return false;
        retainedSpans += spans.size();
        item.add("address_spans", spans);
        cov.add("address_spans", facet(spans.size(), mapped, spans.size() < mapped, null, "complete"));
        return true;
    }

    JsonObject facet(int emitted, int total, boolean truncated, String err, String status) {
        JsonObject f = new JsonObject(); f.addProperty("emitted", emitted);
        if (total < 0) f.add("total", JsonNull.INSTANCE); else f.addProperty("total", total);
        f.addProperty("truncated", truncated); put(f, "error", err);
        f.addProperty("status", err != null && !err.isEmpty() ? "error" : truncated ? "partial" : status);
        if (truncated || (err != null && !err.isEmpty())) partial = true;
        return f;
    }

    boolean append(JsonArray array, JsonObject value, boolean metadata) {
        long bytes = JSON.toJson(value).getBytes(StandardCharsets.UTF_8).length + 1L;
        if (retainedBytes + bytes > (metadata ? METADATA_BUDGET : PAYLOAD_BUDGET)) {
            root.addProperty("output_budget_reached", true); partial = true; return false;
        }
        array.add(value); retainedBytes += bytes; return true;
    }

    boolean appendOption(JsonObject options, String name, String value) {
        // Charge each key/value before retaining it. Counting only at the end
        // could let a large option set consume the whole output allowance.
        String key = clipped(name, MAX_TEXT);
        JsonObject entry = new JsonObject();
        put(entry, key, value);
        long bytes = JSON.toJson(entry).getBytes(StandardCharsets.UTF_8).length + 1L;
        if (retainedBytes + bytes > METADATA_BUDGET) {
            root.addProperty("output_budget_reached", true); partial = true; return false;
        }
        options.add(key, entry.get(key)); retainedBytes += bytes; return true;
    }

    void put(JsonObject obj, String key, String value) {
        if (value == null) obj.add(key, JsonNull.INSTANCE); else obj.addProperty(key, clipped(value, MAX_TEXT));
    }

    String clipped(String value, int max) {
        if (value == null || value.length() <= max) return value;
        textTruncated = true;
        int end = max;
        if (end > 0 && Character.isHighSurrogate(value.charAt(end - 1))) end--;
        return value.substring(0, end);
    }

    static String address(Address a) {
        if (a == null) return null;
        if (!a.isMemoryAddress()) return a.toString();
        // Qualify non-default spaces instead of pretending every address is a VA.
        if (a.getAddressSpace().isOverlaySpace()) return a.toString();
        return "0x" + Long.toUnsignedString(a.getOffset(), 16);
    }

    String error(Exception e) { return clipped(e.getClass().getSimpleName() + ": " + e.getMessage(), MAX_TEXT); }

    static int boundedInt(String text, int min, int max, String name) {
        int value = Integer.parseInt(text);
        if (value < min || value > max) throw new IllegalArgumentException(name + " must be " + min + ".." + max);
        return value;
    }

    static String hex(byte[] bytes) {
        char[] chars = new char[bytes.length * 2]; String alphabet = "0123456789abcdef";
        for (int i = 0; i < bytes.length; i++) { chars[i * 2] = alphabet.charAt((bytes[i] >>> 4) & 15); chars[i * 2 + 1] = alphabet.charAt(bytes[i] & 15); }
        return new String(chars);
    }

    void writeAtomic(Path target) throws IOException {
        // Do not create arbitrary parent paths. The CLI creates a private job dir.
        Path parent = target.getParent();
        if (parent == null || !Files.isDirectory(parent)) throw new IOException("Output parent must already exist");
        byte[] data = JSON.toJson(root).getBytes(StandardCharsets.UTF_8);
        if (data.length > MAX_OUTPUT) throw new IOException("Result exceeds hard 64 MiB output bound");
        Path temp = Files.createTempFile(parent, ".macscope-result-", ".tmp",
            PosixFilePermissions.asFileAttribute(PosixFilePermissions.fromString("rw-------")));
        try {
            try (OutputStream stream = Files.newOutputStream(temp)) { stream.write(data); }
            // No non-atomic fallback: a failed publish must preserve an old result.
            Files.move(temp, target, StandardCopyOption.ATOMIC_MOVE, StandardCopyOption.REPLACE_EXISTING);
        } finally { Files.deleteIfExists(temp); }
    }
}
