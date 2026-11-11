"""Offline packaged-entry smoke using owned bytes, no Ghidra or app execution.

Run with the installed package's Python from outside a source checkout.
"""
import hashlib
import json
from pathlib import Path
import struct
import subprocess
import sys
import tempfile

from macscope import cli, import_disasm, storage


def main():
    def command(kind, data):
        return struct.pack('<II', kind, len(data)+8)+data
    section=struct.pack('<16s16s2Q8I',b'__text',b'__TEXT',0x568,0x64,0x568,2,0,0,0x80000400,0,0,0)
    segment=struct.pack('<16s4Q4I',b'__TEXT',0,0x700,0,0x700,7,5,1,0)
    commands=command(0x19,segment+section)+command(0x26,struct.pack('<II',0x650,6))
    raw=bytearray(struct.pack('<8I',0xfeedfacf,0x100000c,0,2,2,len(commands),0,0)+commands)
    raw.extend(bytes(0x700-len(raw)))
    raw[0x568:0x570]=bytes.fromhex('010000f9c0035fd6')
    raw[0x5c0:0x5cc]=bytes.fromhex('e10300aa800a40f9e8ffff17')
    raw[0x650:0x656]=bytes.fromhex('e80a08401000')
    raw=bytes(raw)
    digest=hashlib.sha256(raw).hexdigest()
    with tempfile.TemporaryDirectory() as temporary:
        p=storage.Project.create(Path(temporary)/'project')
        image={'image_id':digest,'arch':'arm64','sha256':digest,'artifact_sha256':digest,
               'offset':'0x0','engine_baseline_sha256':'a'*64}
        (p.path/'inputs'/(digest+'.macho')).write_bytes(raw)
        with p.db(readonly=False) as db:
            db.execute('INSERT INTO images VALUES(?,?,?,?,?)',(digest,'arm64',json.dumps(image),1,None))
        for job,start,end in [('b'*32,0x5c0,0x5cc),('c'*32,0x568,0x570)]:
            proof,payload=import_disasm.selection(raw,image,start,end)
            binding=import_disasm.binding(p,image,proof)
            (p.path/'jobs'/job).mkdir()
            rows=[{'addr':hex(start+i),'bytes':payload[i:i+4].hex(),'mnemonic':'owned','text':'owned'}
                  for i in range(0,len(payload),4)]
            response=cli.envelope('disasm',{'selection':binding,'instructions':rows,'gaps':[],
                                          'covered_bytes':len(payload),'origin':{'job_id':job}})
            import_disasm.publish(p,{'job_id':job,'status':'complete','mode':'query','disasm_request':binding},response)
        before={str(path.relative_to(p.path)):path.read_bytes() for path in (p.path/'jobs').rglob('*') if path.is_file()}
        args=[sys.executable,'-m','macscope','disasm','--project',str(p.path),'--from-import',
              '--range','0x5c0:0x5cc','--receipt','b'*32,'--callback-evidence','--callback-provenance',
              '--callback-target-receipt','c'*32,'--format','json','--ghidra','/nonexistent/ghidra',
              '--java-home','/nonexistent/java']
        first=subprocess.run(args,cwd=temporary,capture_output=True,text=True,check=True)
        second=subprocess.run(args,cwd=temporary,capture_output=True,text=True,check=True)
        assert first.stdout==second.stdout
        result=json.loads(first.stdout)['data']['callback_evidence']
        relation,=result['destination_link']['store_relations']
        assert result['status']=='inconclusive'
        assert result['destination_link']['status']=='verified_direct_entry_link'
        assert relation['basis']=='byte_proven_register_correspondence'
        assert relation['base_correspondence']['value']['kind']=='memory_read'
        assert relation['value_correspondence']['value']['register']=='x0'
        assert relation['abi_hypothesis'] is None
        after={str(path.relative_to(p.path)):path.read_bytes() for path in (p.path/'jobs').rglob('*') if path.is_file()}
        assert before==after
    print('PASS: packaged two-receipt writer-path replay; no engine, new jobs or receipt mutations')


if __name__=='__main__':
    main()
