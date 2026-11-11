"""Structural diagnostics do not choose speculative callback targets."""
import copy
import unittest
from macscope import callback_composition as c
import test_callback_composition as fixtures


def store(value, *, site='0x10', lane=None):
    row={'kind':'memory_store','instruction_va':site,'value':value}
    if lane is not None: row['lane']=lane
    return row


def report(sites, **kw):
    return dict({'sites':sites,'source_envelope_sha256':'a'*64,'selection':{'start_va':'0x10','end_va':'0x20'},
                 'stop_reason':'selected_prefix_end','gaps':[]}, **kw)


class AssignmentDiagnosticTests(unittest.TestCase):
    def test_empty_and_unresolved_and_wrong_address_are_distinct(self):
        for sites,expected in (([],'no_stores_in_decoded_prefix'),
            ([store({'kind':'range_input_register','register':'x21'})],'no_address_valued_store'),
            ([store({'kind':'integer_constant','value':'0x100'})],'no_address_valued_store'),
            ([store({'kind':'address','value':'0x200'})],'no_matching_address_store')):
            d=c.assignment_diagnostic(report(sites),'0x100')
            self.assertEqual(d['reason'],expected)
            self.assertEqual(d['expected_thunk_entry'],'0x100')
            self.assertTrue(d['next_evidence'])

    def test_ambiguity_unpaired_and_unique_pair(self):
        addr={'kind':'address','value':'0x100'}
        for sites,reason in (([store(addr),store(addr,site='0x14')],'multiple_matching_address_stores'),
            ([store(addr)],'unique_match_without_unique_companion_lane'),
            ([store(addr,lane=0),store({'kind':'range_input_register'},lane=1)],'unique_matching_pair_observed')):
            d=c.assignment_diagnostic(report(sites),'0x100');self.assertEqual(d['reason'],reason)
        self.assertEqual(d['counts'],dict(stores=2,address_valued=1,matching_address=1,other_address=0,non_address=1,unique_match_companion_lanes=1))

    def test_prefix_barrier_and_identity_survive(self):
        r=report([],stop_reason='unsupported_instruction_boundary',gaps=[{'reason':'unsupported'}])
        before=copy.deepcopy(r);d=c.assignment_diagnostic(r,'0x100')
        self.assertEqual(d['stop_reason'],'unsupported_instruction_boundary')
        self.assertEqual(d['gap_count'],1);self.assertEqual(d['selection'],r['selection'])
        self.assertEqual(d['source_envelope_sha256'],'a'*64);self.assertEqual(r,before)
        d['selection']['start_va']='changed';self.assertNotEqual(d['selection'],r['selection'])

    def test_exact_budget_and_no_recursive_values(self):
        sites=[store({'kind':'register_add_result','recursive':{'huge':'x'*10000}},site=hex(i*4)) for i in range(100)]
        d=c.assignment_diagnostic(report(sites),'0x100')
        self.assertEqual(d['counts']['stores'],100);self.assertEqual(d['omitted_stores'],68)
        self.assertEqual(len(d['observations']),32)
        self.assertNotIn('recursive',str(d));self.assertEqual(d['observations'][-1]['instruction_va'],hex(31*4))


class AssignmentCompositionTests(unittest.TestCase):
    def setUp(self):
        self.fixture = fixtures.CompositionTests()
        self.fixture.setUp()
        self.addCleanup(self.fixture.doCleanups)
        self.addCleanup(self.fixture.tearDown)

    def test_diagnostic_does_not_upgrade_unsupported_pair(self):
        self.fixture.change(0x228,'00000000')
        r=self.fixture.composed()
        self.assertEqual(r['assignment_diagnostic']['reason'],'unique_matching_pair_observed')
        self.assertEqual(r['candidate_status'],'gap')
        self.assertGreater(r['assignment_diagnostic']['gap_count'],0)

    def test_unknown_store_remains_existing_gap(self):
        self.fixture.change(0x220,'00000091085001a9c0035fd6')
        r=self.fixture.composed()
        self.assertEqual(r['assignment_diagnostic']['reason'],'no_address_valued_store')
        self.assertEqual(r['candidate_status'],'gap')
        self.assertIn({'reason':'unique_paired_assignment_not_proven'},r['gaps'])
