"""Small validator for the bundled schema subset, with no runtime dependency."""
import json
import re
from pathlib import Path


def validate(value, schema, where='$'):
    types={'object':lambda x:isinstance(x,dict),'array':lambda x:isinstance(x,list),'string':lambda x:isinstance(x,str),'integer':lambda x:type(x) is int,'boolean':lambda x:type(x) is bool,'null':lambda x:x is None}
    kind=schema.get('type')
    if kind and not any(types[k](value) for k in ([kind] if isinstance(kind,str) else kind)):
        raise ValueError(where+': invalid type')
    if 'const' in schema and value!=schema['const']:raise ValueError(where+': invalid const')
    if 'enum' in schema and value not in schema['enum']:raise ValueError(where+': invalid enum')
    if isinstance(value,dict):
        if not set(schema.get('required',[]))<=set(value):raise ValueError(where+': missing required fields')
        props=schema.get('properties',{})
        if schema.get('additionalProperties') is False and not set(value)<=set(props):raise ValueError(where+': unknown fields')
        for k,v in value.items():
            if k in props:validate(v,props[k],where+'.'+k)
    elif isinstance(value,list):
        if len(value)<schema.get('minItems',0) or len(value)>schema.get('maxItems',float('inf')):raise ValueError(where+': collection bounds')
        for i,item in enumerate(value):validate(item,schema.get('items',{}),where+'['+str(i)+']')
    elif type(value) is int and value<schema.get('minimum',value):raise ValueError(where+': below minimum')
    elif isinstance(value,str) and schema.get('pattern') and not re.search(schema['pattern'],value):raise ValueError(where+': invalid pattern')


def validate_envelope(value):
    validate(value,json.loads((Path(__file__).parent/'envelope.schema.json').read_text()))


def validate_function(value):
    validate(value,json.loads((Path(__file__).parent/'function.schema.json').read_text()))
