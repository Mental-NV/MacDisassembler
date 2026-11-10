"""Opt-in virtual mapping proofs include zero-fill aliases and whole strings."""
import unittest

from macscope.macho_view import MappedImage


BASE = 0x1000


def segment(start,size,*,file_size=0,file_offset=0):
    return {'va':hex(start),'size':hex(size),'file_size':hex(file_size),
            'file_offset':hex(file_offset),'protections':5}


class MappedMetadataViewTests(unittest.TestCase):
    def view(self,extra=(),data=b'x'*20+b'\0'+bytes(43),*,strict=True):
        return MappedImage(data,[segment(BASE,64,file_size=64),*extra],
                           reject_virtual_overlap=strict)

    def test_nested_virtual_overlaps_are_coalesced_with_exact_boundaries(self):
        view = self.view([segment(BASE+8,16),segment(BASE+12,4),segment(BASE+24,8)])
        self.assertEqual(view.ambiguous,[(BASE+8,BASE+32)])
        for start,size in ((BASE,8),(BASE+32,32),(BASE+8,0)):
            view.mapping(start,size)
        for start,size in ((BASE+7,2),(BASE+8,1),(BASE+31,2),(BASE,64)):
            with self.assertRaises(ValueError):
                view.mapping(start,size)
        # Structural extent checks do not stand in for read validation.
        self.assertEqual(view.file_mapping(BASE,64),(0,64,5))

    def test_whole_string_including_nul_requires_unambiguous_bytes(self):
        for offset in (0,10,20):
            with self.subTest(offset=offset),self.assertRaises(ValueError):
                self.view([segment(BASE+offset,1)]).string(BASE)
        self.assertEqual(self.view([segment(BASE+21,1)]).string(BASE),'x'*20)

    def test_empty_and_boundary_touching_segments_are_not_ambiguous(self):
        view = self.view([segment(BASE+16,0),segment(BASE+64,32)])
        self.assertEqual(view.ambiguous,[])
        self.assertEqual(view.string(BASE),'x'*20)

    def test_strict_reads_are_opt_in_for_existing_non_objc_consumers(self):
        view = self.view([segment(BASE+10,1)],strict=False)
        self.assertEqual(view.string(BASE),'x'*20)
        self.assertEqual(view.mapping(BASE,64),(0,64,5))
