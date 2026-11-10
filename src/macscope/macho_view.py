"""File-backed virtual-address reads for data-only Mach-O metadata views."""
from bisect import bisect_right
import struct


class MappedImage:
    def __init__(self, data, segments):
        self.data = data
        self.regions = sorted(
            (int(seg["va"],16), int(seg["va"],16)+int(seg["file_size"],16),
             int(seg["file_offset"],16), seg["protections"])
            for seg in segments if seg["file_offset"] is not None and int(seg["file_size"],16)>0
        )
        if any(first[1]>second[0] for first,second in zip(self.regions,self.regions[1:])):
            raise ValueError("Overlapping file-backed Mach-O mappings")
        self.starts = [region[0] for region in self.regions]

    def mapping(self, va, size):
        index = bisect_right(self.starts,va)-1
        if index<0 or size<0:
            raise ValueError("Address is not file-backed")
        lo,hi,file_offset,protections = self.regions[index]
        if va+size>hi:
            raise ValueError("Range crosses a file-backed mapping")
        return file_offset+va-lo, hi-va, protections

    def unpack(self, layout, va):
        offset,_,_ = self.mapping(va,struct.calcsize(layout))
        return struct.unpack_from(layout,self.data,offset)

    def string(self, va):
        offset,remaining,_ = self.mapping(va,1)
        end = self.data.find(b"\0",offset,offset+min(4097,remaining))
        if end<=offset:
            raise ValueError("Missing or oversized metadata string")
        return self.data[offset:end].decode("utf-8","backslashreplace")
