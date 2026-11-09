#!/bin/bash
# run_baseline.sh — direct full-Ghidra headless baseline (Phase 1).
# For each analyst input: import + default auto-analysis + MacscopeBaseline
# post script. No CLI wrapper involved; this IS the engine baseline.
#
# Binary-only hygiene:
#   * inputs come only from build/analyst/<case> (binary alone: no dSYM,
#     no source, no link maps in that directory tree);
#   * -scriptPath points ONLY at analysis/scripts (repo-owned), never at
#     analyst input dirs; no -librarySearchPaths; Ghidra performs no
#     network symbol lookup by default;
#   * isolation gap (honest): no macOS sandbox/sandbox-exec is applied;
#     the run is an ordinary child process restricted to our own fixture
#     inputs. See docs/phase1-findings.md. No untrusted inputs are used.
set -euo pipefail
umask 077

REPO="$(cd "$(dirname "$0")/.." && pwd)"
GH=/opt/homebrew/opt/ghidra/libexec
export JAVA_HOME=/opt/homebrew/Cellar/openjdk@25/25.0.5.0.3/libexec/openjdk.jdk/Contents/Home
export PATH="$JAVA_HOME/bin:$PATH"

ANALYST="$REPO/build/analyst"
WS="$REPO/build/workspaces"
SCRIPTS="$REPO/analysis/scripts"
MAXCPU=4
ANALYSIS_TIMEOUT=600
DECOMPILE_TIMEOUT=30
MAXFUNCS=5000

CASES=(
  "DebugAnalysis-arm64-sym"
  "DebugAnalysis-arm64-stripped"
  "DebugAnalysis-x86_64-sym"
  "DebugAnalysis-x86_64-stripped"
  "ReleaseAnalysis-arm64-sym"
  "ReleaseAnalysis-arm64-stripped"
  "ReleaseAnalysis-x86_64-sym"
  "ReleaseAnalysis-x86_64-stripped"
)

if [ $# -gt 0 ]; then
  CASES=("$@")
fi

echo "java: $(java -version 2>&1 | head -1)"
echo "ghidra: $GH"
HEADLESS=("$GH/support/analyzeHeadless")
if command -v sandbox-exec >/dev/null && sandbox-exec -f "$REPO/analysis/nonet.sb" true 2>/dev/null; then
  echo "isolation: sandbox-exec deny-network profile ACTIVE (tested)"
  HEADLESS=(sandbox-exec -f "$REPO/analysis/nonet.sb" "$GH/support/analyzeHeadless")
else
  echo "isolation: NO sandbox (gap documented; inputs limited to own fixtures)"
fi

for CASE in "${CASES[@]}"; do
  APP_BIN="$ANALYST/$CASE/CalculatorFixture.app/Contents/MacOS/CalculatorFixture"
  TOOL_BIN="$ANALYST/$CASE/CorpusFixture"
  for TARGET in "app:$APP_BIN" "tool:$TOOL_BIN"; do
    KIND="${TARGET%%:*}"
    INPUT="${TARGET#*:}"
    TAG="$CASE-$KIND"
    OUT="$WS/ghidra-$TAG"
    mkdir -p "$OUT"
    PROJ="$OUT/project"
    JSON="$OUT/baseline.json"
    rm -rf "$PROJ"
    mkdir -p "$PROJ"
    echo "=== baseline $TAG ==="
    echo "input: $INPUT"
    echo "sha256: $(shasum -a 256 "$INPUT" | cut -d' ' -f1)"
    START=$(date +%s)
    set +e
    "${HEADLESS[@]}" "$PROJ" "proj_$TAG" \
        -import "$INPUT" \
        -postScript MacscopeBaseline.java "$JSON" "$MAXFUNCS" "$DECOMPILE_TIMEOUT" \
        -scriptPath "$SCRIPTS" \
        -max-cpu "$MAXCPU" \
        -analysisTimeoutPerFile "$ANALYSIS_TIMEOUT" \
        > "$OUT/headless.log" 2>&1
    CODE=$?
    set -e
    END=$(date +%s)
    echo "exit=$CODE elapsed=$((END-START))s"
    echo "$CASE $KIND exit=$CODE elapsed=$((END-START))s" >> "$WS/timings.txt"
    if [ -f "$JSON" ]; then
      echo "sha256: $(shasum -a 256 "$JSON" | cut -d' ' -f1)  $JSON"
      python3 -c "import json;d=json.load(open('$JSON'));print('functions:',d['function_count_enumerated'],'completed:',d['decompile_summary_completed'],'timeout:',d['decompile_summary_timed_out'],'failed:',d['decompile_summary_failed'],'notreq:',d['decompile_summary_not_requested']);print('lang:',d['language_id'],'|',d['compiler_spec_id'])"
    else
      echo "NO BASELINE JSON for $TAG (see $OUT/headless.log)"
    fi
  done
done

echo "=== LLVM disassembly (independent reference) ==="
mkdir -p "$WS"
for CASE in "${CASES[@]}"; do
  case "$CASE" in
    *-arm64-*) LLVMARCH=arm64 ;;
    *-x86_64-*) LLVMARCH=x86_64 ;;
  esac
  ABI="$ANALYST/$CASE/CalculatorFixture.app/Contents/MacOS/CalculatorFixture"
  TBI="$ANALYST/$CASE/CorpusFixture"
  xcrun llvm-objdump --macho --arch="$LLVMARCH" --disassemble "$ABI" > "$WS/llvm-$CASE-app.txt" 2>&1 || echo "llvm failed: $CASE app"
  xcrun llvm-objdump --macho --arch="$LLVMARCH" --disassemble "$TBI" > "$WS/llvm-$CASE-tool.txt" 2>&1 || echo "llvm failed: $CASE tool"
done
echo "llvm disassembly retained under $WS/llvm-*.txt"
xcrun llvm-objdump --version | head -2
