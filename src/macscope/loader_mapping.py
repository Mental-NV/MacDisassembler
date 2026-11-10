"""Compare loaded import mappings with the staged thin Mach-O's declarations."""
from bisect import bisect_right
from pathlib import PurePosixPath

from .errors import Error
from .metadata import VA


def default_address(value):
    return isinstance(value, str) and VA.fullmatch(value) is not None


def observed_sources(blocks, image):
    filename = image["image_id"] + ".macho"
    size = int(image["size"], 16)
    sources = []
    for block in blocks:
        if (block.get("type") != "Default" or block.get("loaded") is not True
                or block.get("initialized") is not True
                or not all(default_address(block.get(key)) for key in ("start", "end"))):
            continue  # Overlay and synthetic memory cannot prove a Mach-O VA mapping.
        lo, hi = int(block["start"], 16), int(block["end"], 16) + 1
        records = block.get("sources")
        if not isinstance(records, list):
            raise Error("loader_mapping_evidence", "Ghidra memory block lacks source records", 10)
        for source in records:
            if not isinstance(source, dict) or "file_offset" not in source:
                raise Error("loader_mapping_evidence", "Invalid Ghidra memory source", 10)
            offset = source["file_offset"]
            if offset is None:
                continue
            name = source.get("file_name")
            if not isinstance(name, str) or not all(default_address(source.get(key)) for key in ("start", "end")):
                raise Error("loader_mapping_evidence", "Invalid Ghidra file-backed source", 10)
            start, end = int(source["start"], 16), int(source["end"], 16) + 1
            if (type(offset) is not int or not lo <= start < end <= hi
                    or not 0 <= offset <= size - (end - start)):
                raise Error("loader_mapping_evidence", "Ghidra file-backed source exceeds its block or slice", 10)
            if PurePosixPath(name).name != filename:
                raise Error("loader_mapping_mismatch", "Ghidra loaded memory from a different file")
            sources.append((start, end, offset))
    sources.sort()
    if overlaps(sources):
        raise Error("loader_mapping_evidence", "Ghidra reported overlapping file-backed sources", 10)
    return sources


def overlaps(ranges):
    return any(left[1] > right[0] for left, right in zip(ranges, ranges[1:]))


def verify(result, image):
    base = result.get("image_base")
    if not default_address(base):
        raise Error("loader_mapping_evidence", "Ghidra image base is missing or invalid", 10)
    preferred = image["loader"]["preferred_image_base"]
    if preferred is not None and int(preferred, 16) != int(base, 16):
        raise Error("loader_mapping_mismatch", "Ghidra image base differs from the Mach-O preferred base")

    blocks = result.get("sections")
    facet = result["coverage"].get("sections")
    if (not isinstance(blocks, list) or not isinstance(facet, dict)
            or type(facet.get("emitted")) is not int or facet["emitted"] != len(blocks)):
        raise Error("loader_mapping_evidence", "Ghidra memory block coverage is missing or invalid", 10)
    sources = observed_sources(blocks, image)
    declared = sorted((int(row["va"], 16), int(row["va"], 16) + int(row["size"], 16),
                       int(row["file_offset"], 16)) for row in image["sections"]
                      if row["file_offset"] is not None and int(row["size"], 16))
    gaps = []
    if preferred is None:
        gaps.append("preferred_base_unavailable")
    if (facet.get("status") != "complete" or facet.get("truncated") is not False
            or facet.get("error") is not None or facet.get("total") != len(blocks)
            or any(row.get("sources_truncated") is not False for row in blocks)):
        gaps.append("worker_mapping_incomplete")

    verified = 0
    if overlaps(declared):
        gaps.append("ambiguous_declared_sections")
    else:
        starts = [source[0] for source in sources]
        for start, end, offset in declared:
            index = max(0, bisect_right(starts, start) - 1)
            covered = 0
            while index < len(sources) and sources[index][0] < end:
                lo, hi, backing = sources[index]
                length = min(hi, end) - max(lo, start)
                if length > 0:
                    if backing - lo != offset - start:
                        raise Error("loader_mapping_mismatch", "Ghidra file mapping differs from a Mach-O section")
                    covered += length
                index += 1
            verified += covered == end - start
        if verified < len(declared):
            gaps.append("declared_sections_unmapped")
        if not declared:
            gaps.append("no_file_backed_sections")

    return {"status": "partial" if gaps else "verified", "image_base": base,
            "declared_file_backed_sections": len(declared), "verified_sections": verified, "coverage_gaps": gaps}
