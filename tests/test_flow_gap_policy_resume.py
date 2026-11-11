"""Current-policy receipts and immutable v2/v3 replay using owned saved slices."""
import copy
import json
from unittest.mock import patch

from macscope import engine, flow_gap_classification, flow_gap_evidence, focused, jobs, storage
import test_flow_gap_evidence


class CurrentPolicyReceiptTests(test_flow_gap_evidence.GapReceiptTests):
    def test_default_v4_request_and_v2_gap_policy_are_bound(self):
        self.assertEqual(self.proof['policy'], 'macscope-focused-import/4')
        self.assertEqual(self.proof['flow_gap_classification']['policy'], flow_gap_classification.POLICY)
        result = self.capture()
        self.assertEqual(result['data']['origin']['extent'], self.proof)
        self.assertEqual(result['data']['control_flow_gaps'][0]['evidence']['policy'],
                         'macscope-control-flow-gap-evidence/2')
        self.assertEqual(self.request['extent'], self.proof)

    def test_current_raw_gaps_and_evidence_cannot_be_removed_or_fabricated_after_rehash(self):
        self.capture()
        path = self.workspace.path / 'jobs' / self.original / 'query-result.json'
        original = json.loads(path.read_bytes())
        mutations = {
            'remove_all_gaps': lambda f: f.pop('control_flow_gaps'),
            'empty_gaps': lambda f: f.update(control_flow_gaps=[]),
            'remove_all_evidence': lambda f: [g.pop('evidence') for g in f['control_flow_gaps']],
            'duplicate_gap': lambda f: f['control_flow_gaps'].append(copy.deepcopy(f['control_flow_gaps'][0])),
            'invent_raw_warning': lambda f: f['control_flow_gaps'][0].update(warning='invented'),
            'invent_raw_site': lambda f: f['control_flow_gaps'][0].update(**{'from':self.entry}),
        }
        for name, mutate in mutations.items():
            with self.subTest(name=name):
                self.assert_rejected_after_rehash(original, mutate)

    def test_current_forged_classification_and_request_proof_fail_production_receipts(self):
        self.capture()
        path = self.workspace.path / 'jobs' / self.original / 'query-result.json'
        original = json.loads(path.read_bytes())
        fake = {'kind':'verified_linkage_boundary','reason':'ordinary_import_pointer_sequence',
                'runtime_target':'unresolved','proof':{'source_va':self.entry,'source_bytes':self.code.hex(),
                'bind_va':self.entry,'binding':{'symbol':'_objc_msgSend'}}}
        mutations = {
            'positive_linkage_from_warning': lambda f: f['control_flow_gaps'][0]['evidence'].update(classification=fake),
            'unsupported_runtime_target': lambda f: f['control_flow_gaps'][0]['evidence']['classification'].update(runtime_target=self.entry),
            'plan_coverage_reason': lambda f: f['origin']['extent']['flow_gap_classification'].update(reason='candidate_limit'),
            'plan_extra_field': lambda f: f['origin']['extent']['flow_gap_classification'].update(runtime_callee='_owned'),
            'plan_fake_candidate': lambda f: f['origin']['extent']['flow_gap_classification']['candidates'].append(fake['proof']),
        }
        for name, mutate in mutations.items():
            with self.subTest(name=name):
                self.assert_rejected_after_rehash(original, mutate)

    def test_rehashed_request_plan_is_recomputed_from_saved_slice_before_launch(self):
        # This is structurally valid but not the plan derived from the saved RET.
        corrupt_proof = copy.deepcopy(self.proof)
        corrupt_proof['flow_gap_classification']['reason'] = 'candidate_limit'
        flow_gap_classification.validate_plan(corrupt_proof['flow_gap_classification'])
        request = jobs.focused_request(self.workspace, self.image, corrupt_proof)
        self.write_job(self.original, dict(self.record, focused_import=corrupt_proof, focused_request=request))
        with patch.object(engine, 'run', side_effect=AssertionError('A forged plan must not launch')):
            self.error('job_resume_inputs', self.resume)

    def test_unfinished_v2_keeps_v2_and_legacy_gap_evidence_during_capture_and_replay(self):
        proof, _ = focused.select(self.workspace, self.image, self.entry, policy='macscope-focused-import/2')
        self.proof = dict(proof, program_sha256=self.image['engine_baseline_sha256'])
        self.request = jobs.focused_request(self.workspace, self.image, self.proof)
        self.record.update(focused_import=self.proof, focused_request=self.request)
        self.write_job(self.original, self.record)
        result = self.capture()
        self.assertEqual(result['data']['origin']['extent']['policy'], 'macscope-focused-import/2')
        self.assertNotIn('flow_gap_classification', result['data']['origin']['extent'])
        self.assertEqual(result['data']['control_flow_gaps'][0]['evidence']['policy'], flow_gap_evidence.LEGACY_POLICY)
        self.assertEqual(result['data']['control_flow_gaps'][0]['evidence']['classification'],
                         {'kind':'unclassified','reason':'classification_not_evaluated'})
        path = self.workspace.path / 'jobs' / self.original / 'query-result.json'
        before = path.read_bytes()
        with patch.object(engine, 'run', side_effect=AssertionError('Completed v2 must remain offline')), \
                patch.object(engine, 'dependencies', side_effect=AssertionError('No Java probe on replay')):
            replay = self.resume()
        self.assertEqual(replay['data']['control_flow_gaps'], result['data']['control_flow_gaps'])
        self.assertEqual(path.read_bytes(), before)

    def test_unfinished_v3_keeps_exact_v3_proof_during_capture_and_replay(self):
        proof, _ = focused.select(self.workspace,self.image,self.entry,policy='macscope-focused-import/3')
        self.proof=dict(proof,program_sha256=self.image['engine_baseline_sha256'])
        self.request=jobs.focused_request(self.workspace,self.image,self.proof)
        self.record.update(focused_import=self.proof,focused_request=self.request)
        self.write_job(self.original,self.record)
        result=self.capture()
        self.assertEqual(result['data']['origin']['extent'],self.proof)
        self.assertEqual(result['data']['origin']['extent']['policy'],'macscope-focused-import/3')
        self.assertEqual(result['data']['control_flow_gaps'][0]['evidence']['policy'],flow_gap_evidence.POLICY)
        path=self.workspace.path/'jobs'/self.original/'query-result.json';before=path.read_bytes()
        with patch.object(engine,'run',side_effect=AssertionError('No v3 worker relaunch')), \
                patch.object(engine,'dependencies',side_effect=AssertionError('No engine probe')):
            replay=self.resume()
        self.assertEqual(replay['data']['origin']['extent'],self.proof)
        self.assertEqual(replay['data']['control_flow_gaps'],result['data']['control_flow_gaps'])
        self.assertEqual(path.read_bytes(),before)
