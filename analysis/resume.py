from pathlib import Path
import json,re
ROOT=Path(__file__).resolve().parent.parent/'.scan_state'
def safe(v): return re.sub(r'[^A-Za-z0-9._-]+','_',str(v or '').strip())[:100] or 'scan'
def path_for(target): return ROOT/f'{safe(target)}.json'
def load_state(target):
    try:
        d=json.loads(path_for(target).read_text(encoding='utf-8')); return d if isinstance(d,dict) else {'target':target,'completed':[],'data':{}}
    except Exception: return {'target':target,'completed':[],'data':{}}
def save_stage(target,stage,data):
    state=load_state(target); state.setdefault('completed',[]); state.setdefault('data',{})
    if stage not in state['completed']: state['completed'].append(stage)
    state['data'][stage]=data; ROOT.mkdir(parents=True,exist_ok=True); p=path_for(target); p.write_text(json.dumps(state,indent=2,ensure_ascii=False),encoding='utf-8'); return str(p)
def clear_state(target):
    try: path_for(target).unlink()
    except FileNotFoundError: pass
