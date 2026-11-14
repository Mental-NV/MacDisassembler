import tempfile
from pathlib import Path
import unittest
from unittest.mock import patch
from integration_shared_import import run,validate_orders,validate_output

class SharedHarnessTests(unittest.TestCase):
    def test_orders_bounded_and_unique_preparation(self):
        validate_orders([2,1,0],[0,1,2,0,1])
        for prep,calls in [([0,0,2],[0]),([0,1,True],[0]),([0,1,2],[]),([0,1,2],[0]*7),([0,1,2],[3]),([0,1,2],[True])]:
            with self.subTest(prep=prep,calls=calls),self.assertRaises(ValueError):validate_orders(prep,calls)
    def test_existing_output_refuses_launch(self):
        with tempfile.TemporaryDirectory() as tmp,patch('subprocess.run') as proc:
            with self.assertRaises(FileExistsError):run(Path(tmp))
            proc.assert_not_called()
    def test_result_membership_and_complete_required(self):
        value={'schema':'owned-shared-import/1','semantics':'shared-import-preparation','prepared':[{'entry':e} for e in ['0x1','0x2','0x3']], 'calls':[{'entry':'0x1','completed':True,'pseudocode':'return 1;'}]}
        self.assertIs(validate_output(value,['0x1','0x2','0x3'],[0]),value)
        value['calls'][0]['completed']=False
        with self.assertRaises(ValueError):validate_output(value,['0x1','0x2','0x3'],[0])
        value['calls'][0]['completed']=True
        with self.assertRaises(ValueError):validate_output(value,['0x1','0x2','0x3'],[1])
