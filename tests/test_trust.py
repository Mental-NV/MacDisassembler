"""Invocation consent and partial-output compatibility, without native execution."""
import argparse
import io
import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch
from macscope import cli, engine, trust
from macscope.errors import Error


class TrustTests(unittest.TestCase):
    def decide(self, answer, tty=True):
        args = argparse.Namespace(experimental_trusted_input=False)
        stream = io.StringIO(answer)
        with patch.object(stream, 'isatty', return_value=tty), patch.object(trust.sys, 'stdin', stream), patch.object(trust.sys, 'stderr', io.StringIO()):
            trust.require(args)
        return args

    def test_affirmative(self):
        for answer in ('yes\n', 'Y\n', ' YES \n'):
            self.assertTrue(self.decide(answer).experimental_trusted_input)

    def test_denial_eof_and_non_tty(self):
        for answer, tty in [('no\n', True), ('', True), ('\n', True), ('yes please\n', True), ('yes\n', False)]:
            with self.subTest(answer=answer, tty=tty), self.assertRaises(Error) as raised:
                self.decide(answer, tty)
            self.assertEqual((raised.exception.code, raised.exception.exit_code), ('isolation_required', 3))

    def test_explicit_does_not_read_stdin(self):
        with patch.object(trust.sys, 'stdin') as stream:
            trust.require(argparse.Namespace(experimental_trusted_input=True))
            stream.isatty.assert_not_called()

    def test_flags_for_native_commands(self):
        commands = [
            ['import','owned','--project','p'], ['analyze','--project','p'],
            ['decompile','--fresh','--address','0x1000','--project','p'],
            ['decompile','--from-import','--address','0x1000','--project','p'],
            ['jobs','resume','a'*32,'--project','p'],
            ['doctor','--verify-worker'], ['demangle','owned'],
            ['swift','symbols','--demangle','--project','p'],
        ]
        for command in commands:
            for flag in ('--trust-input', '--experimental-trusted-input'):
                with self.subTest(command=command, flag=flag):
                    self.assertTrue(cli.parser().parse_args([*command, flag]).experimental_trusted_input)

    def test_denied_native_demangle_never_runs(self):
        with patch.object(trust.sys.stdin, 'isatty', return_value=False), patch.object(cli.swift_symbols, 'demangle') as native:
            with self.assertRaises(Error):
                cli.execute(cli.parser().parse_args(['demangle','owned']))
            native.assert_not_called()

    def test_denied_doctor_never_loads_dependencies(self):
        with patch.object(trust.sys.stdin, 'isatty', return_value=False), patch.object(engine, 'dependencies') as native:
            with self.assertRaises(Error):
                cli.execute(cli.parser().parse_args(['doctor','--verify-worker']))
            native.assert_not_called()

    def test_partial_output_preserved_and_explained(self):
        for fmt in ('json','text','jsonl'):
            result = cli.envelope('evidence', {'leads':[{'status':'unresolved','reason':'missing_writer','gaps':['indirect_target']}]},
                                  status='partial', cov=cli.coverage(partial=True, reason='lead_evidence_incomplete'))
            with tempfile.TemporaryDirectory() as root:
                output = Path(root)/'result'
                args = argparse.Namespace(command='evidence',format=fmt,output=str(output),force=False)
                with patch.object(cli,'parser') as parser, patch.object(cli,'execute',return_value=result), patch.object(cli,'protect_output'):
                    parser.return_value.parse_args.return_value = args
                    self.assertEqual(cli.main([]),6)
                text = output.read_text()
                self.assertIn('missing_writer', text)
                self.assertIn('lead_evidence_incomplete',text)
                self.assertIn('not an engine crash',text)
                self.assertIn('individual links',text)

    def test_failed_timeout_cancelled_remain_errors(self):
        for code, exit_code, status in [('worker_failed',10,'failed'),('worker_timeout',7,'failed'),('cancelled',130,'cancelled')]:
            stdout = io.TextIOWrapper(io.BytesIO(), encoding='utf-8')
            with patch.object(cli,'execute',side_effect=Error(code,code,exit_code)), patch.object(cli.sys,'stdout',stdout), patch.object(cli.sys,'stderr',io.StringIO()):
                self.assertEqual(cli.main(['version']),exit_code)
                result = json.loads(stdout.buffer.getvalue())
            self.assertEqual(result['status'],status)
            self.assertEqual(result['error']['code'],code)
            self.assertNotIn('not an engine crash',str(result))

    def test_denied_resume_does_not_load_native_dependencies(self):
        with patch.object(trust.sys.stdin,'isatty',return_value=False), patch.object(engine,'dependencies') as deps:
            with self.assertRaises(Error) as raised:
                cli.replay_worker_request(argparse.Namespace(experimental_trusted_input=False),None,{})
            self.assertEqual(raised.exception.code,'isolation_required')
            deps.assert_not_called()

    def test_public_help_does_not_require_authorship(self):
        self.assertNotIn('owned fixtures only',cli.parser().format_help())
        self.assertIn('trusted inputs',cli.parser().format_help())

    def test_partial_dot_retains_warning(self):
        result=cli.envelope('cfg',{'blocks':[]},status='partial',cov=cli.coverage(partial=True))
        self.assertIn(b'Partial result (exit 6)',cli.render(result,'dot'))

    def test_analysis_limitations_do_not_require_authorship(self):
        profile = engine.analysis_profile()
        raw = {'language_id': 'AARCH64:LE:64:v8A', 'compiler_spec_id': 'default',
               'status': 'complete', 'functions': []}
        image = {'image_id': '1' * 64, 'sha256': '2' * 64, 'arch': 'arm64'}
        with patch.object(engine, 'validate_analysis_profile'):
            record = cli.normalize(raw, image, {}, {'analysis_profile': profile, 'limits': {}})
        text = ' '.join(record['limitations'])
        self.assertNotIn('trusted owned fixtures', text)
        self.assertIn('Only explicitly trusted inputs are supported', text)
        self.assertIn('hostile-input isolation is not validated', text)
