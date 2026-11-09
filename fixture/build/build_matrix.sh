#!/bin/bash
# build_matrix.sh — Phase 1 build/test matrix for the calculator fixture.
#
# Outputs (all under ignored build/ paths; nothing committed):
#   <output>/evaluator/<cfg>-<arch>/   link products, dSYMs, LinkMaps (evaluator)
#   <output>/analyst/<case>/            symbol-preserving + stripped copies (analyst)
#   <output>/universal/<name>.app       four universal parity containers
#   <output>/manifest.json              full command/version/UUID/hash record
#   <output>/build.log                  complete log of this run
#
# Fails fast if core tests or UI journeys fail.
set -euo pipefail
umask 077

REPO="$(cd "$(dirname "$0")/../.." && pwd)"
FIX="$REPO/fixture"
BLD="${1:-$REPO/build/matrix-$(date -u +%Y%m%dT%H%M%SZ)-$$}"
# Run evidence is append-only: never reuse an output directory.
if [ -e "$BLD" ]; then echo "refusing existing build output: $BLD" >&2; exit 2; fi
mkdir -p "$BLD"
BLD="$(cd "$BLD" && pwd)"
cd "$REPO"
export MACSCOPE_BUILD_ROOT="$BLD"
EV="$BLD/evaluator"
AN="$BLD/analyst"
UNI="$BLD/universal"
LOG="$BLD/build.log"
mkdir -p "$EV" "$AN" "$UNI"

exec > >(tee "$LOG") 2>&1
set -x # retain actual commands and expanded arguments, including tool flags

echo "=== Phase 0: durable tests (fail fast) ==="
xcrun clang -O0 -g -Wall -Wextra -std=c11 -Ifixture/src \
    fixture/src/calc_core.c fixture/tests/calc_core_tests.c \
    -o "$BLD/calc_core_tests" 2>&1
"$BLD/calc_core_tests"
xcrun clang -O0 -g -Wall -fobjc-arc -Ifixture/src -framework Cocoa \
    fixture/src/calc_core.c fixture/src/CalcController.m \
    fixture/tests/ui_journeys.m -o "$BLD/ui_journeys" 2>&1
"$BLD/ui_journeys"

echo "=== Toolchain versions ==="
sw_vers
xcodebuild -version
xcrun --sdk macosx --show-sdk-version
xcrun clang --version | head -2
python3 --version

echo "=== Matrix builds via shared scheme ==="
for CFG in DebugAnalysis ReleaseAnalysis; do
  for ARCH in arm64 x86_64; do
    OUT="$EV/$CFG-$ARCH"
    mkdir -p "$OUT"
    echo "--- build $CFG $ARCH ---"
    /usr/bin/time -p xcodebuild \
        -project "$FIX/CalculatorFixture.xcodeproj" \
        -scheme CalculatorFixture \
        -configuration "$CFG" \
        -derivedDataPath "$BLD/derived/$CFG-$ARCH" \
        CONFIGURATION_BUILD_DIR="$OUT" \
        ARCHS="$ARCH" ONLY_ACTIVE_ARCH=NO \
        build > "$BLD/xcodebuild-$CFG-$ARCH.log" 2>&1
    tail -3 "$BLD/xcodebuild-$CFG-$ARCH.log"
    echo "built $CFG-$ARCH"
  done
done

echo "=== Analyst copies + strip ==="
STRIP_CMD="xcrun strip"
for CFG in DebugAnalysis ReleaseAnalysis; do
  for ARCH in arm64 x86_64; do
    SRC_APP="$EV/$CFG-$ARCH/CalculatorFixture.app"
    SRC_BIN="$SRC_APP/Contents/MacOS/CalculatorFixture"
    SRC_TOOL="$EV/$CFG-$ARCH/CorpusFixture"
    for TARGET in app tool; do
      if [ "$TARGET" = app ]; then SRCF="$SRC_BIN"; else SRCF="$SRC_TOOL"; fi
      for STATE in sym stripped; do
        D="$AN/$CFG-$ARCH-$STATE"
        mkdir -p "$D"
        if [ "$TARGET" = app ]; then
          /usr/bin/ditto "$SRC_APP" "$D/CalculatorFixture.app"
          DSTF="$D/CalculatorFixture.app/Contents/MacOS/CalculatorFixture"
        else
          cp "$SRCF" "$D/CorpusFixture"
          DSTF="$D/CorpusFixture"
        fi
        if [ "$STATE" = stripped ]; then
          $STRIP_CMD "$DSTF"
          codesign -s - --force "$DSTF"
          if [ "$TARGET" = app ]; then
            codesign -s - --force "$D/CalculatorFixture.app"
          fi
        fi
      done
    done
  done
done

echo "=== Section-byte verification (strip must not touch __text) ==="
: > "$BLD/strip-verify.txt"
for CFG in DebugAnalysis ReleaseAnalysis; do
  for ARCH in arm64 x86_64; do
    for B in "CalculatorFixture.app/Contents/MacOS/CalculatorFixture" "CorpusFixture"; do
      A="$AN/$CFG-$ARCH-sym/$B"; S="$AN/$CFG-$ARCH-stripped/$B"
      HA=$(python3 "$FIX/build/write_manifest.py" --text-hash "$A")
      HB=$(python3 "$FIX/build/write_manifest.py" --text-hash "$S")
      if [ "$HA" = "$HB" ]; then R=PRESERVED; else R=CHANGED; fi
      echo "$CFG-$ARCH $B __text $R $HA" | tee -a "$BLD/strip-verify.txt"
      [ "$R" = PRESERVED ]
    done
  done
done

echo "=== Universal containers ==="
# Ad-hoc signatures cover the whole file, so signing the universal would
# rewrite bytes inside each slice. Build universals from signature-removed
# copies (static analysis does not consume signatures), sign the universal
# once, and require byte-identical slice parity against those copies plus
# __text-hash parity against the signed thin analyst inputs.
for CFG in DebugAnalysis ReleaseAnalysis; do
  for STATE in sym stripped; do
    U="$UNI/CalculatorFixture-$CFG-$STATE.app"
    [ ! -e "$U" ] # isolated run must never replace a prior product
    /usr/bin/ditto "$AN/$CFG-arm64-$STATE/CalculatorFixture.app" "$U"
    BIN="$U/Contents/MacOS/CalculatorFixture"
    for ARCH in arm64 x86_64; do
      cp "$AN/$CFG-$ARCH-$STATE/CalculatorFixture.app/Contents/MacOS/CalculatorFixture" \
         "$BLD/nosig-$CFG-$STATE-$ARCH"
      codesign --remove-signature "$BLD/nosig-$CFG-$STATE-$ARCH"
    done
    xcrun lipo -create \
        "$BLD/nosig-$CFG-$STATE-arm64" "$BLD/nosig-$CFG-$STATE-x86_64" \
        -output "$BIN"
    codesign -s - --force "$BIN"
    codesign -s - --force "$U"
    xcrun lipo -info "$BIN"
    for ARCH in arm64 x86_64; do
      xcrun lipo -thin "$ARCH" "$BIN" -output "$BLD/slice-$CFG-$STATE-$ARCH"
      # Exact parity is only meaningful pre-signing: compare against the
      # same unsigned payload, then strip the universal's fresh signature
      # for the comparison so file bytes line up.
      cp "$BLD/slice-$CFG-$STATE-$ARCH" "$BLD/slice-$CFG-$STATE-$ARCH.chk"
      codesign --remove-signature "$BLD/slice-$CFG-$STATE-$ARCH.chk"
      cmp "$BLD/slice-$CFG-$STATE-$ARCH.chk" "$BLD/nosig-$CFG-$STATE-$ARCH"
      echo "parity ok: $CFG $STATE $ARCH"
      # __text parity against the signed thin analyst input.
      HT=$(python3 "$FIX/build/write_manifest.py" --text-hash \
          "$AN/$CFG-$ARCH-$STATE/CalculatorFixture.app/Contents/MacOS/CalculatorFixture")
      HU=$(python3 "$FIX/build/write_manifest.py" --text-hash "$BLD/slice-$CFG-$STATE-$ARCH")
      [ "$HT" = "$HU" ]
      echo "text parity ok: $CFG $STATE $ARCH"
    done
  done
done

echo "=== Reference outputs (evaluator side, arm64 only — never run x86_64) ==="
for CFG in DebugAnalysis ReleaseAnalysis; do
  "$EV/$CFG-arm64/CorpusFixture" > "$EV/reference-outputs-$CFG.txt"
  echo "--- $CFG ---"; head -8 "$EV/reference-outputs-$CFG.txt"
done

echo "=== App launch smoke omitted: controller journeys own test scope; no user sessions touched ==="

echo "=== Manifest ==="
python3 "$FIX/build/write_manifest.py" "$REPO" "$BLD"
echo "=== DONE: all fail-fast build/test/parity stages succeeded ==="
