"""Validate text offsets and preserve only spans bound to the displayed text."""
import re


VA = re.compile(r"0x[0-9a-f]{1,16}")


def outcome(function, *, engine=False):
    state = function.get("decompile_status")
    if engine:
        state = function.get("engine_decompile_status", state)
    if state == "complete" and (function.get("pseudocode_truncated") or not function.get("pseudocode")):
        return "partial"
    return state if isinstance(state, str) else "unknown"


def address_spans(function, displayed_text):
    original = function.get("pseudocode")
    spans = function.get("address_spans", [])
    coverage = function.get("coverage", {}).get("address_spans", {})
    status = coverage.get("status")
    if original != displayed_text:
        return [], {"available": False, "status": "unavailable",
                    "reason": "Displayed pseudocode was redacted"}
    if not spans:
        return [], {"available": False,
                    "status": status or "unavailable",
                    "reason": coverage.get("reason") or ("Address span limit reached" if status == "partial"
                                                        else "No address-bearing tokens from Ghidra")}
    if (not original or status not in ("complete", "partial")
            or coverage.get("emitted") != len(spans)):
        raise ValueError("Inconsistent pseudocode address-span coverage")

    utf16 = original.encode("utf-16-le", errors="surrogatepass")
    utf16_size = len(utf16) // 2
    previous = 0
    for span in spans:
        start, end = span["text_start"], span["text_end"]
        if type(start) is not int or type(end) is not int or not previous <= start < end <= utf16_size:
            raise ValueError("Invalid pseudocode address-span text offsets")
        if any(0 < offset < utf16_size and 0xD8 <= utf16[offset * 2 - 1] <= 0xDB
               and 0xDC <= utf16[offset * 2 + 1] <= 0xDF for offset in (start, end)):
            raise ValueError("Pseudocode address-span offset splits a UTF-16 surrogate pair")
        ranges = span["ranges"]
        if not ranges or any(not VA.fullmatch(lo) or not VA.fullmatch(hi) or int(lo, 16) > int(hi, 16)
                             for lo, hi in ranges):
            raise ValueError("Invalid pseudocode address-span machine ranges")
        previous = end
    return spans, {"available": True, "status": status, "text_offsets": "utf16",
                   "reason": "Address span limit reached" if status == "partial" else None}
