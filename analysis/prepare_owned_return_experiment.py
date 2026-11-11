"""Generate an explicitly assumed, disposable experimental bridge; never patch source in place.

Usage: python prepare_owned_return_experiment.py BASELINE.java OUTPUT.java '0x1,0x2'
The caller must bind each listed entry to the frozen owned return fixture. This is
not a product option or metadata-driven inference. Only int64_t is experimental.
"""
import hashlib
import json
from pathlib import Path
import re
import sys

EXPECTED='212678fe1487e48c7b883a67b721cf5bd50ffbeba2ee60483dae0595cdf62964'
OLD='''                if (fromImport) {
                    item = function(f, new BasicBlockModel(currentProgram), opened ? decomp : null, timeout);
                } else {'''


def prepare(source, destination, entries):
    if source.resolve()==destination.resolve() or destination.exists():
        raise ValueError('Require a new disposable output path, not an in-place product edit')
    if not 1<=len(entries)<=3 or len(set(entries))!=len(entries) or any(not re.fullmatch(r'0x[0-9a-f]{1,16}',e) for e in entries):
        raise ValueError('Require one to three explicit owned selected entries')
    raw=source.read_bytes()
    if hashlib.sha256(raw).hexdigest()!=EXPECTED:raise ValueError('Unexpected baseline bridge')
    text=raw.decode();assert text.count(OLD)==1
    selection=', '.join(json.dumps(e) for e in entries)
    replacement='''                if (fromImport) {
                    // OWNED FEASIBILITY ONLY: explicit assumption, not inferred metadata.
                    boolean assumed = Set.of(SELECTION).contains(entry);
                    if (assumed && !f.getName().contains("OwnedReturnChannels")) {
                        throw new IllegalArgumentException("Assumption is restricted to the owned fixture");
                    }
                    String previousReturn = f.getReturnType().getDisplayName();
                    String previousSignature = f.getSignature().toString();
                    SourceType previousSource = f.getSignatureSource();
                    String previousStorage = f.getReturn().getVariableStorage().toString();
                    int experimentTransaction = currentProgram.startTransaction("Owned return assumption (rollback)");
                    try {
                        if (assumed) {
                            f.setReturnType(scalarHintType("int64_t"), SourceType.USER_DEFINED);
                            decomp.flushCache();
                        }
                        item = function(f, new BasicBlockModel(currentProgram), opened ? decomp : null, timeout);
                    } finally {
                        currentProgram.endTransaction(experimentTransaction, false);
                    }
                    if (!previousReturn.equals(f.getReturnType().getDisplayName()) ||
                        !previousSignature.equals(f.getSignature().toString()) ||
                        previousSource != f.getSignatureSource() ||
                        !previousStorage.equals(f.getReturn().getVariableStorage().toString())) {
                        Function restored = functionAt(entry);
                        throw new IllegalStateException("Owned experiment failed to restore return declaration" +
                            "; return=" + previousReturn + " -> " + f.getReturnType().getDisplayName() +
                            "; signature=" + previousSignature + " -> " + f.getSignature().toString() +
                            "; source=" + previousSource + " -> " + f.getSignatureSource() +
                            "; storage=" + previousStorage + " -> " + f.getReturn().getVariableStorage().toString() +
                            "; freshReturn=" + restored.getReturnType().getDisplayName() +
                            "; freshSource=" + restored.getSignatureSource());
                    }
                } else {'''.replace('SELECTION',selection)
    output=text.replace(OLD,replacement).encode()
    with destination.open('xb') as stream:stream.write(output)
    print(json.dumps({'experiment_only':True,'explicit_assumption':'int64_t selected return',
                      'owned_entries':entries,'baseline_sha256':EXPECTED,
                      'experimental_bridge_sha256':hashlib.sha256(output).hexdigest()},indent=2))


if __name__=='__main__':prepare(Path(sys.argv[1]),Path(sys.argv[2]),sys.argv[3].split(','))
