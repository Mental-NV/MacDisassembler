"""Manual expression-model comparison, NOT compiled-code execution/equivalence.

Run with the owned evidence directory. Guard exact native pseudocode hashes so
this handwritten interpretation cannot silently validate different output.
"""
import hashlib
import itertools
import json
from pathlib import Path
import sys

EXPECTED = {
 'arm64-contains':'d9c44c82ac38a5ef11ac582f14236113322752bfc52b79d5435c7f048d5f433f',
 'arm64-clamp':'2fc8f52b8e08d12b80b2646f521caf12d60ddcaa29cc46318d24da55f0113a83',
 'arm64-select':'acd8fee2f072b2b212610ae65daff0cdbc1c3f645deefc537eee2735ebbf25be',
 'x86_64-contains':'4bf379c5c5ab86fc0764c9150c39c2f7d59f7e00cd284c484bf44ac030331741',
 'x86_64-clamp':'830ec4a8076cf74446b3cbc0947bb7ca40962ee1f5e00b9576a2aa8bd064ff11',
 'x86_64-select':'1a05fa07488009cb3b85cae82bb58f9e9b7105d3a88d96df360915e99c86dccb',
}
MASK=(1<<64)-1
SIGN=1<<63
VALUES=[-SIGN,-SIGN+1,-100,-2,-1,0,1,2,7,31,100,SIGN-2,SIGN-1]
POINTERS=[0,1,2,SIGN-1,SIGN,MASK]


def signed(value):return value-(1<<64) if value&SIGN else value


def source_clamp(day,limit):
    if limit<=0:return -1
    if day<0:return 0
    if day>=limit:return limit-1
    return day


def observed_arm_clamp(day,limit):
    p3,p4=day&MASK,limit&MASK
    u2=p3
    if p4<=p3:u2=(p4-1)&MASK
    u1=0
    if p3&SIGN==0:u1=u2
    u2=MASK
    if 0<signed(p4):u2=u1
    return u2


def observed_x86_clamp(day,limit):
    p3,p4=day&MASK,limit&MASK
    if signed(p4)<1:return MASK
    if signed(p3)<0:return 0
    u1=(p4-1)&MASK
    if p3<p4:u1=p3
    return u1


def run(directory):
    for name,digest in EXPECTED.items():
        data=json.loads((directory/(name+'.json')).read_text())['data']
        if hashlib.sha256(data['pseudocode'].encode()).hexdigest()!=digest:
            raise ValueError('Native pseudocode changed: '+name)
    counts={}
    for arch in ('arm64','x86_64'):
        count=0
        for day,lower,upper in itertools.product(VALUES,repeat=3):
            expected=lower<=day<=upper
            observed=(lower<=day and day<=upper) if arch=='arm64' else (day<=upper and lower<=day)
            assert observed==expected
            count+=1
        for day,limit in itertools.product(VALUES,repeat=2):
            observed=(observed_arm_clamp if arch=='arm64' else observed_x86_clamp)(day,limit)
            assert observed==source_clamp(day,limit)&MASK
            count+=1
        # Valid _Bool arguments only. No promise about nonconforming incoming bits.
        for primary,fallback,enabled in itertools.product(POINTERS,POINTERS,(0,1)):
            expected=primary if enabled and primary else fallback
            if arch=='arm64':
                observed=primary
                if ((primary!=0)&enabled)==0:observed=fallback
            else:
                observed=fallback
                if enabled!=0:observed=primary
                if primary==0:observed=fallback
            assert observed==expected
            count+=1
        counts[arch]=count
    print(json.dumps({'manual_expression_cases':counts,'mismatches':0,
                      'limitation':'Hand-translated expression models only; no binary or recovered-C execution.'},indent=2))


if __name__=='__main__':run(Path(sys.argv[1]))
