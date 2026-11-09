// Trusted pre-analysis profile. This is hygiene, not a filesystem sandbox.
import java.util.Map;
import java.util.TreeMap;
import ghidra.app.script.GhidraScript;
import ghidra.framework.options.Options;
import ghidra.framework.options.OptionType;
import ghidra.program.model.listing.Program;

public class MacscopeBlindProfile extends GhidraScript {
    public void run() throws Exception {
        Options options = currentProgram.getOptions(Program.ANALYSIS_PROPERTIES);
        // Set even when a particular analyzer is inapplicable and unregistered.
        options.setBoolean("DWARF", false);
        options.setBoolean("PDB", false);
        options.setBoolean("External Symbol Resolver", false);
        boolean dwarfSeen = false;
        for (String name : options.getOptionNames()) {
            String root = name.split("\\.", 2)[0];
            String lower = root.toLowerCase(java.util.Locale.ROOT);
            if (root.equals("DWARF")) dwarfSeen = true;
            if (name.equals(root) && options.getType(name) == OptionType.BOOLEAN_TYPE &&
                (lower.contains("dwarf") || lower.contains("pdb") || lower.contains("dsym") ||
                 lower.contains("source") || lower.equals("external symbol resolver"))) {
                options.setBoolean(name, false);
                println("Blind profile disables: " + name);
            }
        }
        if (!dwarfSeen || options.getBoolean("DWARF", true)) {
            throw new IllegalStateException("DWARF disablement could not be verified");
        }
        currentProgram.getOptions(Program.PROGRAM_INFO).setString("Macscope Blind Profile", "binary-only-v2");
        // No external libraries loaded by runner's explicit Mach-O loader flags.
    }
}
