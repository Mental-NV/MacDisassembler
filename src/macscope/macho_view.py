"""File-backed virtual-address reads for data-only Mach-O metadata views."""
from bisect import bisect_right
import struct


class MappedImage:
    def __init__(self, data, segments, *, reject_virtual_overlap=False):
        self.data = data
        self.regions = sorted(
            (int(seg["va"],16), int(seg["va"],16)+int(seg["file_size"],16),
             int(seg["file_offset"],16), seg["protections"])
            for seg in segments if seg["file_offset"] is not None and int(seg["file_size"],16)>0
        )
        if any(first[1]>second[0] for first,second in zip(self.regions,self.regions[1:])):
            raise ValueError("Overlapping file-backed Mach-O mappings")
        self.starts = [region[0] for region in self.regions]
        # Optional metadata-read proof. File-backed regions alone do not reveal
        # a second segment's zero-fill range shadowing the same virtual bytes.
        # Compute overlap intervals once so each read remains logarithmic.
        self.ambiguous = []
        if reject_virtual_overlap:
            events = {}
            for segment in segments:
                start = int(segment["va"],16)
                end = start+int(segment["size"],16)
                if end > start:
                    events[start] = events.get(start,0)+1
                    events[end] = events.get(end,0)-1
            count,previous = 0,None
            for at in sorted(events):
                if previous is not None and count > 1 and previous < at:
                    if self.ambiguous and self.ambiguous[-1][1] == previous:
                        self.ambiguous[-1] = (self.ambiguous[-1][0],at)
                    else:
                        self.ambiguous.append((previous,at))
                count += events[at]
                previous = at
        self.ambiguous_starts = [start for start,_ in self.ambiguous]

    def file_mapping(self, va, size):
        """Check structural file extent only; not proof of readable VA bytes."""
        index = bisect_right(self.starts,va)-1
        if index<0 or size<0:
            raise ValueError("Address is not file-backed")
        lo,hi,file_offset,protections = self.regions[index]
        if va+size>hi:
            raise ValueError("Range crosses a file-backed mapping")
        return file_offset+va-lo, hi-va, protections

    def mapping(self, va, size):
        result = self.file_mapping(va,size)
        if size:
            index = bisect_right(self.ambiguous_starts,va+size-1)-1
            if index >= 0 and self.ambiguous[index][1] > va:
                raise ValueError("Read overlaps ambiguous virtual Mach-O mappings")
        return result

    def unpack(self, layout, va):
        offset,_,_ = self.mapping(va,struct.calcsize(layout))
        return struct.unpack_from(layout,self.data,offset)

    def string(self, va):
        offset,remaining,_ = self.mapping(va,1)
        end = self.data.find(b"\0",offset,offset+min(4097,remaining))
        if end<=offset:
            raise ValueError("Missing or oversized metadata string")
        # The first byte alone cannot prove the remainder, including the NUL,
        # comes from one unambiguous mapping.
        self.mapping(va,end-offset+1)
        return self.data[offset:end].decode("utf-8","backslashreplace")
