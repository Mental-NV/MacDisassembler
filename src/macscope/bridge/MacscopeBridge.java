// Narrow, bounded exporter of a real Ghidra Program. Ghidra 12.2 public APIs.
// analyzeHeadless ... -postScript MacscopeBridge.java OUTPUT MODE MAXFUNCS TIMEOUT [QUERY_ENTRY]
// MODE: import (no function work), analyze (post-analysis), query (read-only).
// The runner owns import/process/readOnly/noanalysis flags and project locking.
import java.io.IOException;
import java.io.OutputStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;
import java.nio.file.attribute.PosixFilePermissions;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Locale;
import java.util.Map;

import com.google.gson.Gson;
import com.google.gson.GsonBuilder;
import com.google.gson.JsonArray;
import com.google.gson.JsonNull;
import com.google.gson.JsonObject;
import com.google.gson.JsonParser;
import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileOptions;
import ghidra.app.decompiler.DecompileResults;
import ghidra.app.util.headless.HeadlessScript;
import ghidra.framework.options.Options;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressIterator;
import ghidra.program.model.address.AddressRange;
import ghidra.program.model.address.AddressRangeIterator;
import ghidra.program.model.block.BasicBlockModel;
import ghidra.program.model.block.CodeBlock;
import ghidra.program.model.block.CodeBlockIterator;
import ghidra.program.model.block.CodeBlockReference;
import ghidra.program.model.block.CodeBlockReferenceIterator;
import ghidra.program.model.listing.Data;
import ghidra.program.model.listing.DataIterator;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionIterator;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.InstructionIterator;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.model.mem.MemoryBlockSourceInfo;
import ghidra.program.model.symbol.ExternalLocation;
import ghidra.program.model.symbol.Reference;
import ghidra.program.model.symbol.ReferenceIterator;
import ghidra.program.model.symbol.Symbol;
import ghidra.program.model.symbol.SymbolIterator;
import ghidra.program.model.symbol.SymbolTable;

public class MacscopeBridge extends HeadlessScript {
    static final String SCHEMA = "macscope-bridge/1";
    static final String VERSION = "1.2.0";
    static final String PROFILE = "macscope-binary-only/1";
    static final String PARAMETER_PROFILE = "macscope-binary-only-parameters/1";
    static final int MAX_INSTRUCTIONS = 2000, MAX_BLOCKS = 500, MAX_EDGES = 500;
    static final int MAX_XREFS = 200, MAX_RANGES = 512, MAX_SECTIONS = 2048;
    static final int MAX_SYMBOLS = 10000, MAX_STRINGS = 5000, MAX_SCAN = 100000;
    static final int MAX_OPTIONS = 4096, MAX_TEXT = 4096, MAX_PSEUDOCODE = 1048576;
    static final long MAX_OUTPUT = 64L * 1024 * 1024;
    static final long PAYLOAD_BUDGET = 56L * 1024 * 1024;
    static final long METADATA_BUDGET = 16L * 1024 * 1024;
    static final Gson JSON = new GsonBuilder().serializeNulls().disableHtmlEscaping().create();

    final JsonObject root = new JsonObject();
    final JsonArray errors = new JsonArray(), warnings = new JsonArray();
    final JsonObject coverage = new JsonObject();
    final JsonObject summary = new JsonObject();
    long retainedBytes = 0;
    boolean partial = false, fatal = false, textTruncated = false;
    int attempted = 0, completed = 0, timedOut = 0, failed = 0, cancelled = 0, notRequested = 0;
    String mode, decompilerError;

    @Override
    public void run() throws Exception {
        String[] args = getScriptArgs();
        if (args.length != 4 && args.length != 5) {
            throw new IllegalArgumentException("Usage: MacscopeBridge.java OUTPUT import|analyze|query MAXFUNCS FUNCTION_TIMEOUT [QUERY_ENTRY]");
        }
        mode = args[1];
        if (!mode.equals("import") && !mode.equals("analyze") && !mode.equals("query")) {
            throw new IllegalArgumentException("Unsupported bridge mode: " + mode);
        }
        int maxFunctions = boundedInt(args[2], 1, 10000, "MAXFUNCS");
        int timeout = boundedInt(args[3], 1, 300, "FUNCTION_TIMEOUT");
        String entry = args.length == 5 ? args[4] : null;
        if (entry != null && (!mode.equals("query") || maxFunctions != 1 || !entry.matches("0x[0-9a-f]{1,16}"))) {
            throw new IllegalArgumentException("Selected decompilation requires query mode and one RAM entry");
        }
        Path output = Path.of(args[0]).toAbsolutePath().normalize();
        root.addProperty("schema", SCHEMA);
        root.addProperty("bridge_version", VERSION);
        root.addProperty("mode", mode);
        if (entry != null) root.addProperty("selected_entry", entry);
        root.addProperty("ghidra_version", getGhidraVersion());
        root.add("errors", errors);
        root.add("warnings", warnings);
        root.add("coverage", coverage);
        root.add("decompile_summary", summary);
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
        limits.addProperty("body_ranges_per_function", MAX_RANGES);
        limits.addProperty("sections", MAX_SECTIONS);
        limits.addProperty("symbols_per_category", MAX_SYMBOLS);
        limits.addProperty("strings", MAX_STRINGS);
        limits.addProperty("defined_data_scan", MAX_SCAN);
        limits.addProperty("option_names_per_category", MAX_OPTIONS);
        limits.addProperty("text_characters", MAX_TEXT);
        limits.addProperty("pseudocode_characters_per_function", MAX_PSEUDOCODE);
        root.add("limits", limits);
        try {
            if (!"12.2".equals(getGhidraVersion())) {
                throw new IllegalStateException("Bridge is pinned to Ghidra 12.2");
            }
            if (currentProgram == null) throw new IllegalStateException("No loaded Program");
            describeProgram();
            describeOptions();
            verifyMode();
            if (entry == null) {
                sections();
                symbols();
                imports();
                exports();
                strings();
            }
            if (!fatal && !mode.equals("import")) functions(maxFunctions, timeout, entry);
            else coverage.add("functions", facet(0, 0, false, null,
                mode.equals("import") ? "not_requested" : "failed"));
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
            if ((!PROFILE.equals(appliedProfile) && !PARAMETER_PROFILE.equals(appliedProfile)) ||
                !info.getBoolean("Macscope Profile Applied", false)) {
                fatal = true; errors.add("Required binary-only pre-analysis profile was not applied");
            }
        }
        if (analysisTimeoutOccurred()) { partial = true; warnings.add("Ghidra autoanalysis reached its deadline; exported evidence is partial"); }
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
                    if (si.getFileBytes().isPresent()) source.addProperty("file_offset", si.getFileBytesOffset());
                    else source.add("file_offset", JsonNull.INSTANCE);
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
            DataIterator it = currentProgram.getListing().getDefinedData(true);
            while (scanned < MAX_SCAN && out.size() < MAX_STRINGS && it.hasNext()) {
                monitor.checkCancelled(); Data data = it.next(); scanned++;
                if (!data.hasStringValue()) continue;
                JsonObject item = new JsonObject(); put(item, "address", address(data.getAddress()));
                item.addProperty("length_bytes", data.getLength());
                if (data.getLength() > MAX_TEXT * 4) {
                    put(item, "value", null); item.addProperty("value_truncated", true); partial = true;
                } else {
                    Object value = data.getValue(); String str = value == null ? null : value.toString();
                    put(item, "value", str); item.addProperty("value_truncated", str != null && str.length() > MAX_TEXT);
                }
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

    void functions(int limit, int timeout, String entry) {
        JsonArray out = root.getAsJsonArray("functions");
        DecompInterface decomp = new DecompInterface();
        String err = null; boolean trunc = false; int visited = 0;
        try {
            DecompileOptions opts = new DecompileOptions();
            opts.setDefaultTimeout(timeout); opts.setMaxInstructions(100000);
            opts.setMaxJumpTableEntries(4096); opts.setMaxPayloadMBytes(8);
            decomp.setOptions(opts); decomp.toggleCCode(true); decomp.toggleSyntaxTree(false);
            boolean opened = decomp.openProgram(currentProgram);
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
                Address selectedAddress = currentProgram.getAddressFactory().getDefaultAddressSpace().getAddress(entry.substring(2));
                Function f = currentProgram.getFunctionManager().getFunctionAt(selectedAddress);
                if (f == null) throw new IllegalStateException("Selected entry is absent from saved Program");
                monitor.checkCancelled();
                JsonObject item = new JsonObject(), facets = new JsonObject();
                item.add("coverage", facets);
                put(item, "entry_va", address(f.getEntryPoint()));
                decompile(f, opened ? decomp : null, timeout, item, facets);
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

    JsonObject function(Function f, BasicBlockModel model, DecompInterface decomp, int timeout) {
        JsonObject item = new JsonObject(), cov = new JsonObject();
        item.add("coverage", cov); put(item, "name", f.getName());
        put(item, "namespace", f.getParentNamespace().getName(true)); put(item, "entry_va", address(f.getEntryPoint()));
        item.addProperty("is_external", f.isExternal()); item.addProperty("is_thunk", f.isThunk());
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

    void decompile(Function f, DecompInterface decomp, int timeout, JsonObject item, JsonObject cov) {
        String status, err = null, code = null; boolean trunc = false;
        if (f.isExternal() || f.isThunk()) {
            status = "not_requested"; notRequested++;
            err = f.isExternal() ? "External function has no body in this image" : "Thunk forwards to another function";
        } else {
            attempted++;
            if (decomp == null) {
                status = "failed"; err = "Decompiler failed to open Program: " + decompilerError; failed++;
            } else {
                try {
                    DecompileResults result = decomp.decompileFunction(f, timeout, monitor);
                    if (result == null) { status = "failed"; err = "Native decompiler returned null results"; failed++; }
                    else {
                        err = result.getErrorMessage();
                        if (result.isTimedOut()) { status = "timeout"; timedOut++; }
                        else if (result.isCancelled()) { status = "cancelled"; cancelled++; }
                        else if (result.failedToStart()) { status = "failed"; failed++; }
                        else if (result.decompileCompleted() && result.getDecompiledFunction() != null &&
                                 result.getDecompiledFunction().getC() != null) {
                            status = "complete"; completed++; code = result.getDecompiledFunction().getC();
                            trunc = code.length() > MAX_PSEUDOCODE;
                            if (trunc) code = clipped(code, MAX_PSEUDOCODE);
                        } else { status = "failed"; failed++; }
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
