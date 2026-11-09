// Test a binary-derived function join on a disposable read-only Program copy.
//@category Macscope research
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressIterator;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionManager;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.symbol.ReferenceIterator;
import ghidra.program.model.symbol.SourceType;

public class JoinUnconfirmedFallthrough extends GhidraScript {
    @Override
    public void run() throws Exception {
        if (!isRunningHeadless()) {
            throw new IllegalStateException("Use a disposable read-only headless Program copy");
        }
        String[] args = getScriptArgs();
        if (args.length != 3) {
            throw new IllegalArgumentException("Expected owner entry, competing entry and next linker start");
        }
        Address entry = toAddr(args[0]);
        Address competing = toAddr(args[1]);
        Address nextStart = toAddr(args[2]);
        FunctionManager manager = currentProgram.getFunctionManager();
        Function owner = manager.getFunctionAt(entry);
        Function extra = manager.getFunctionAt(competing);
        Instruction previous = currentProgram.getListing().getInstructionBefore(competing);
        if (owner == null || extra == null || owner.isExternal() || extra.isExternal() ||
            owner.isThunk() || extra.isThunk() || extra.getSymbol().getSource() != SourceType.DEFAULT ||
            previous == null || !owner.getBody().contains(previous.getAddress()) ||
            !competing.equals(previous.getFallThrough()) || !competing.equals(previous.getMaxAddress().next())) {
            throw new IllegalStateException("No adjacent fallthrough into a default competing entry");
        }
        AddressSet body = new AddressSet(owner.getBody());
        body.add(extra.getBody());
        if (!body.getMinAddress().equals(entry) || body.getMaxAddress().compareTo(nextStart) >= 0 ||
            body.getNumAddressRanges() != 1) {
            throw new IllegalStateException("Joined body crosses a linker extent or contains a gap");
        }
        var references = currentProgram.getReferenceManager();
        AddressIterator targets = references.getReferenceDestinationIterator(extra.getBody(), true);
        while (targets.hasNext()) {
            monitor.checkCancelled();
            ReferenceIterator refs = references.getReferencesTo(targets.next());
            while (refs.hasNext()) {
                monitor.checkCancelled();
                if (!body.contains(refs.next().getFromAddress())) {
                    throw new IllegalStateException("A reference to the competing body originates outside the joined body");
                }
            }
        }
        int transaction = currentProgram.startTransaction("Macscope temporary fallthrough experiment");
        boolean joined = false;
        try {
            if (!manager.removeFunction(competing)) {
                throw new IllegalStateException("Could not remove the competing function");
            }
            owner.setBody(body);
            joined = true;
            println("MACSCOPE_JOIN_CONFIRMED " + body);
        }
        finally {
            currentProgram.endTransaction(transaction, joined);
        }
    }
}
