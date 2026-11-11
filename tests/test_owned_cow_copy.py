import importlib.util
from pathlib import Path
import tempfile
import unittest
import errno
import os

spec = importlib.util.spec_from_file_location('owned_copy', Path(__file__).parents[1]/'analysis'/'owned_cow_copy.py')
m = importlib.util.module_from_spec(spec); spec.loader.exec_module(m)

class OwnedCopyTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(); self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name); self.src = self.root/'src'; self.src.mkdir()
        (self.src/'empty-directory').mkdir(); (self.src/'zero').touch(); (self.src/'data').write_bytes(b'owned')

    def test_baseline_and_injected(self):
        for method in ['baseline', 'injected-fallback']:
            result = m.copy_tree(self.src, self.root/method, method)
            self.assertTrue(result['distinct_inodes'])
            self.assertEqual(result['source']['rows'], result['destination']['rows'])

    def test_separate_mutation_observations(self):
        dst=self.root/'copy'; baseline=m.copy_tree(self.src,dst,'baseline')
        for kind in ['destination-byte','destination-append']:
            result=m.mutate_and_verify(self.src,dst,'data',kind,baseline['source'])
            self.assertEqual(result['operation'],kind)
            self.assertEqual(result['selected_path'],'data')
            self.assertTrue(result['counterpart_preserved'])
            self.assertEqual(len(result['distinct_inode_pairs_after']),2)
        expected=m.inventory(dst)
        result=m.mutate_and_verify(self.src,dst,'data','source-byte',expected)
        self.assertTrue(result['counterpart_preserved'])
        self.assertEqual(result['counterpart_sha256'],expected['sha256'])

    def test_collisions_and_overlap(self):
        for destination in [self.src, self.src/'nested', self.root]:
            with self.assertRaises(ValueError): m.copy_tree(self.src, destination, 'baseline')
        dst=self.root/'occupied'; dst.mkdir(); (dst/'sentinel').write_text('unchanged')
        with self.assertRaises(FileExistsError): m.copy_tree(self.src,dst,'clone')
        self.assertEqual((dst/'sentinel').read_text(),'unchanged')

    def test_symlink_and_fifo(self):
        (self.src/'link').symlink_to(self.src/'data')
        with self.assertRaises(ValueError): m.inventory(self.src)
        (self.src/'link').unlink(); os.mkfifo(self.src/'fifo')
        with self.assertRaises(ValueError): m.inventory(self.src)

    def test_native_errors_never_silently_fallback(self):
        for error in [errno.ENOTSUP, errno.EXDEV, errno.ENOSYS, errno.EIO, errno.EEXIST]:
            def fail(a,b): raise OSError(error,'test')
            with self.assertRaises(OSError): m.copy_tree(self.src,self.root/str(error),'clone',fail)

    def test_fallback_error_and_partial_destination_controls(self):
        for error in [errno.ENOTSUP, errno.EXDEV, errno.ENOSYS]:
            dst=self.root/f'fallback-{error}'
            def fail(a,b): raise OSError(error,'injected')
            self.assertEqual(m.fallback_file(self.src/'data',dst,fail),error)
            self.assertEqual(dst.read_bytes(),b'owned')
        for error in [errno.EIO,errno.EEXIST,errno.EACCES]:
            def fail(a,b): raise OSError(error,'injected')
            with self.assertRaises(OSError):
                m.fallback_file(self.src/'data',self.root/f'error-{error}',fail)
        dst=self.root/'partial'
        def partial(a,b):
            b.write_bytes(b'partial')
            raise OSError(errno.ENOTSUP,'injected')
        with self.assertRaises(OSError): m.fallback_file(self.src/'data',dst,partial)
        self.assertEqual(dst.read_bytes(),b'partial')

    def test_hardlink_rejected(self):
        with self.assertRaisesRegex(ValueError,'shared inode'):
            m.copy_tree(self.src,self.root/'hardlink','clone',os.link)

    def test_inventory_includes_empty_dirs(self):
        before=m.inventory(self.src); (self.src/'another-empty').mkdir()
        self.assertNotEqual(before['sha256'],m.inventory(self.src)['sha256'])

if __name__=='__main__': unittest.main()
