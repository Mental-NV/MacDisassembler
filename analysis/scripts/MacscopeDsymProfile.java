// Owned-fixture diagnostic with one explicit DWARF companion.
import java.io.InputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.MessageDigest;
import java.util.HexFormat;

import ghidra.app.util.bin.format.dwarf.DWARFImportOptions;
import ghidra.app.util.bin.format.dwarf.DWARFImporter;
import ghidra.app.util.bin.format.dwarf.DWARFProgram;
import ghidra.app.util.bin.format.dwarf.sectionprovider.DSymSectionProvider;
import ghidra.framework.options.Options;
import ghidra.program.model.listing.Program;

public class MacscopeDsymProfile extends MacscopeBlindProfile {
    @Override
    public void run() throws Exception {
        super.run();
        String[] args = getScriptArgs();
        if (args.length != 2) {
            throw new IllegalArgumentException("Expected the staged dSYM file and SHA-256");
        }
        Path debugFile = Path.of(args[0]);
        MessageDigest digest = MessageDigest.getInstance("SHA-256");
        try (InputStream input = Files.newInputStream(debugFile)) {
            byte[] buffer = new byte[64 * 1024];
            int count;
            while ((count = input.read(buffer)) != -1) {
                monitor.checkCancelled();
                digest.update(buffer, 0, count);
            }
        }
        String sha256 = HexFormat.of().formatHex(digest.digest());
        if (!sha256.equals(args[1])) {
            throw new IllegalStateException("Staged dSYM digest differs from the selected companion");
        }

        DWARFImportOptions options = new DWARFImportOptions();
        options.setImportDataTypes(true);
        options.setImportFuncs(true);
        options.setOutputSourceLineInfo(false);
        options.setOutputSourceLocationInfo(false);
        int before = currentProgram.getFunctionManager().getFunctionCount();
        int units;
        try (DWARFProgram dwarf = new DWARFProgram(currentProgram, options,
                new DSymSectionProvider(debugFile.toFile()))) {
            dwarf.init(monitor);
            units = dwarf.getCompilationUnits().size();
            if (units == 0) {
                throw new IllegalStateException("Selected dSYM contains no DWARF compilation units");
            }
            new DWARFImporter(dwarf, monitor).performImport().logSummaryResults();
        }
        int after = currentProgram.getFunctionManager().getFunctionCount();
        if (after <= before) {
            throw new IllegalStateException("Expected the owned dSYM to add functions before autoanalysis");
        }
        Options info = currentProgram.getOptions(Program.PROGRAM_INFO);
        info.setString("Macscope dSYM SHA-256", sha256);
        info.setInt("Macscope dSYM units", units);
        info.setInt("Macscope dSYM functions before", before);
        info.setInt("Macscope dSYM functions after", after);
        info.setString("Macscope Blind Profile", "dsym-assisted-v1");
    }
}
