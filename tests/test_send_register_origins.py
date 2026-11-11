import struct
import unittest
from macscope import send_register_origins as m


def run(words):
    words = words + [0x14000001]
    raw = struct.pack('<'+'I'*len(words), *words)
    class Context:
        binary = raw
        def section(self, address, size, executable=False):
            return {}, address-0x100
    function = {'entry_va':'0x100', 'instructions':[{'addr':hex(0x100+i*4),'bytes':raw[i*4:i*4+4].hex()} for i in range(len(words))]}
    transfer = {'source_va':hex(0x100+(len(words)-1)*4),'source_bytes':raw[-4:].hex()}
    return Context(), function, transfer


def mov(dst, src):
    return 0xaa0003e0 | src<<16 | dst


class RegisterOriginsTests(unittest.TestCase):
    def test_native_move_and_transitive_overwrite(self):
        for words, expected in [([mov(0,2)],'x2'),([mov(9,3),mov(0,9)],'x3'),([mov(0,2),mov(0,5)],'x5'),([], 'x0')]:
            result=m.build(*run(words))
            self.assertEqual(result['receiver_register']['origin']['register'],expected)
            self.assertEqual(result['argument_count_and_types'],'unknown')

    def test_zero_self_and_discard(self):
        r=m.build(*run([mov(0,31),mov(31,2),mov(0,0)]))
        self.assertEqual(r['receiver_register']['origin'],{'kind':'constant','value':'0x0'})

    def test_near_misses_and_barriers(self):
        for word in [mov(0,2)^0x80000000,mov(0,2)|0x400,mov(0,2)|0x200000,mov(0,2)^0x20,
                     0xf9400000,0x94000000,0xd65f03c0,0xd503245f,0xd503233f,0xa9bf7bfd]:
            r=m.build(*run([word,mov(0,2)]))
            self.assertEqual(r['status'],'unavailable',hex(word))
            self.assertNotIn('receiver_register',r)

    def test_bounds_and_bytes(self):
        self.assertIn('receiver_register',m.build(*run([0xd503201f]*32)))
        self.assertEqual(m.build(*run([0xd503201f]*33))['status'],'unavailable')
        c,f,t=run([mov(0,2)]);c.binary=b'\0'*len(c.binary)
        self.assertEqual(m.build(c,f,t)['reason'],'prefix_bytes_mismatch')
        for address in ['0x104','0xfc','0x101']:
            c,f,t=run([mov(0,2)]);f['instructions'][0]['addr']=address
            self.assertEqual(m.build(c,f,t)['status'],'unavailable')
        c,f,t=run([mov(0,2)]);f['instructions'].pop(0)
        self.assertEqual(m.build(c,f,t)['status'],'unavailable')
