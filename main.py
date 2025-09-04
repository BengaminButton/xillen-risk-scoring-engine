import sys
import json
import time
import math
import uuid
import re
from collections import defaultdict

def nid():
    return str(uuid.uuid4())

def now():
    return int(time.time())

def read_json(path):
    with open(path, 'r', encoding='utf-8') as f:
        return json.load(f)

def write_json(path, obj):
    with open(path, 'w', encoding='utf-8') as f:
        json.dump(obj, f, ensure_ascii=False, indent=2)

def to_num(v, d=0.0):
    try:
        return float(v)
    except Exception:
        return d

class AssetStore:
    def __init__(self):
        self.assets = {}
    def load(self, path):
        data = read_json(path)
        for a in data.get('assets', []):
            aid = a.get('id') or nid()
            self.assets[aid] = {
                'id': aid,
                'name': a.get('name', aid),
                'type': a.get('type', ''),
                'tags': list(a.get('tags', [])),
                'criticality': float(a.get('criticality', 0.5))
            }
    def list_ids(self):
        return list(self.assets.keys())
    def get(self, aid):
        return self.assets.get(aid)

class EventStore:
    def __init__(self):
        self.events = []
    def load(self, path):
        data = read_json(path)
        for e in data.get('events', []):
            self.events.append({
                'id': e.get('id') or nid(),
                'ts': int(e.get('ts', now())),
                'asset': e.get('asset'),
                'type': e.get('type', ''),
                'severity': float(e.get('severity', 0.5)),
                'labels': list(e.get('labels', [])),
                'data': e.get('data', {})
            })
    def all(self):
        return list(self.events)

class Rule:
    def __init__(self, r):
        self.id = r.get('id') or nid()
        self.name = r.get('name', self.id)
        self.weight = float(r.get('weight', 1.0))
        self.when = r.get('when', {})
        self.calc = r.get('calc', {})
    def match(self, asset, event):
        cond = self.when
        ok = True
        if 'event_type' in cond:
            ok = ok and (event.get('type') in cond['event_type'])
        if 'asset_type' in cond:
            ok = ok and (asset.get('type') in cond['asset_type'])
        if 'asset_tags_any' in cond:
            tags = set(asset.get('tags', []))
            if not tags.intersection(set(cond['asset_tags_any'])):
                ok = False
        if 'event_labels_any' in cond:
            labs = set(event.get('labels', []))
            if not labs.intersection(set(cond['event_labels_any'])):
                ok = False
        if 'event_severity_gte' in cond:
            ok = ok and (to_num(event.get('severity', 0)) >= float(cond['event_severity_gte']))
        return ok
    def score(self, asset, event):
        c = self.calc
        base = float(c.get('base', 0))
        sev = float(event.get('severity', 0))
        crit = float(asset.get('criticality', 0))
        mul_sev = float(c.get('mul_severity', 0))
        mul_crit = float(c.get('mul_criticality', 0))
        bonus = 0.0
        if 'if_label_bonus' in c:
            for k, v in c['if_label_bonus'].items():
                if k in set(event.get('labels', [])):
                    bonus += float(v)
        if 'if_tag_bonus' in c:
            for k, v in c['if_tag_bonus'].items():
                if k in set(asset.get('tags', [])):
                    bonus += float(v)
        s = base + sev * mul_sev + crit * mul_crit + bonus
        return max(0.0, s * self.weight)

class Policy:
    def __init__(self, data):
        self.id = data.get('id') or nid()
        self.name = data.get('name', self.id)
        self.version = data.get('version', '1.0')
        self.rules = [Rule(r) for r in data.get('rules', [])]
    @staticmethod
    def load(path):
        return Policy(read_json(path))

class RiskEngine:
    def __init__(self, assets, events, policy):
        self.assets = assets
        self.events = events
        self.policy = policy
        self.results = []
        self.by_asset = defaultdict(list)
    def evaluate(self):
        for e in self.events.all():
            a = self.assets.get(e.get('asset'))
            if not a:
                continue
            total = 0.0
            applied = []
            for r in self.policy.rules:
                if r.match(a, e):
                    val = r.score(a, e)
                    if val != 0:
                        applied.append({'rule': r.id, 'name': r.name, 'score': val})
                        total += val
            self.results.append({'event': e['id'], 'asset': a['id'], 'score': total, 'applied': applied, 'ts': e['ts']})
            self.by_asset[a['id']].append(total)
        return self
    def aggregate(self):
        agg = {}
        for aid, vals in self.by_asset.items():
            if not vals:
                continue
            agg[aid] = {
                'count': len(vals),
                'sum': float(sum(vals)),
                'avg': float(sum(vals) / len(vals)),
                'max': float(max(vals)),
                'p95': float(self.percentile(vals, 95)),
                'p99': float(self.percentile(vals, 99)),
            }
        return agg
    @staticmethod
    def percentile(vals, p):
        s = sorted(vals)
        if not s:
            return 0.0
        k = (len(s) - 1) * (p / 100.0)
        f = math.floor(k)
        c = math.ceil(k)
        if f == c:
            return float(s[int(k)])
        d0 = s[int(f)] * (c - k)
        d1 = s[int(c)] * (k - f)
        return float(d0 + d1)

def bootstrap_policy():
    return {
        'id': 'default-policy',
        'name': 'Default Risk Policy',
        'version': '1.0',
        'rules': [
            {
                'id': 'sev-asset',
                'name': 'Severity and criticality',
                'weight': 1.0,
                'when': { 'event_type': ['alert','anomaly','incident'] },
                'calc': { 'base': 0, 'mul_severity': 60, 'mul_criticality': 50 }
            },
            {
                'id': 'label-bonus',
                'name': 'Label bonus',
                'weight': 1.0,
                'when': { 'event_labels_any': ['privilege_escalation','exfil','lateral'] },
                'calc': { 'base': 0, 'if_label_bonus': { 'privilege_escalation': 30, 'exfil': 40, 'lateral': 20 } }
            },
            {
                'id': 'tag-bonus',
                'name': 'Asset tag bonus',
                'weight': 1.0,
                'when': { 'asset_tags_any': ['prod','pci','pii'] },
                'calc': { 'base': 10, 'if_tag_bonus': { 'prod': 20, 'pci': 25, 'pii': 25 } }
            }
        ]
    }

def export_report(path, engine, assets):
    agg = engine.aggregate()
    details = engine.results
    out = {
        'generated_at': now(),
        'authors': 't.me/Bengamin_Button t.me/XillenAdapter',
        'summary': [],
        'details': details
    }
    for aid, metrics in agg.items():
        a = assets.get(aid) or {'id': aid, 'name': aid}
        out['summary'].append({
            'asset': a['id'],
            'name': a.get('name', a['id']),
            'type': a.get('type',''),
            'avg': metrics['avg'],
            'max': metrics['max'],
            'p95': metrics['p95'],
            'p99': metrics['p99'],
            'count': metrics['count']
        })
    out['summary'].sort(key=lambda x: (-x['max'], -x['avg'], x['asset']))
    write_json(path, out)

def load_or_default(path):
    try:
        return Policy.load(path)
    except Exception:
        return Policy(bootstrap_policy())

def read_cli_pairs(values):
    res = {}
    for v in values:
        if '=' in v:
            k, x = v.split('=', 1)
            res[k.strip()] = x.strip()
    return res

def filter_events(events, q):
    if not q:
        return events
    out = []
    et = q.get('type')
    lab = q.get('label')
    aid = q.get('asset')
    for e in events:
        if et and e.get('type') != et:
            continue
        if lab and lab not in set(e.get('labels', [])):
            continue
        if aid and e.get('asset') != aid:
            continue
        out.append(e)
    return out

def fmt_table(rows, cols):
    w = [len(c) for c in cols]
    for r in rows:
        for i, c in enumerate(cols):
            w[i] = max(w[i], len(str(r.get(c, ''))))
    s = []
    s.append(' '.join(c.ljust(w[i]) for i, c in enumerate(cols)))
    s.append(' '.join('-'*w[i] for i in range(len(cols))))
    for r in rows:
        s.append(' '.join(str(r.get(c, '')).ljust(w[i]) for i, c in enumerate(cols)))
    return '\n'.join(s)

def cli():
    if len(sys.argv) < 4:
        print('t.me/Bengamin_Button t.me/XillenAdapter')
        print('usage: main.py assets.json events.json policy.json [cmd] [k=v ...]')
        sys.exit(1)
    assets_path = sys.argv[1]
    events_path = sys.argv[2]
    policy_path = sys.argv[3]
    cmd = sys.argv[4] if len(sys.argv) > 4 else 'report'
    kv = read_cli_pairs(sys.argv[5:])
    assets = AssetStore()
    assets.load(assets_path)
    events = EventStore()
    events.load(events_path)
    policy = load_or_default(policy_path)
    if cmd == 'report':
        eng = RiskEngine(assets, events, policy).evaluate()
        out = kv.get('out', 'risk.report.json')
        export_report(out, eng, assets.assets)
        print(out)
        return
    if cmd == 'top':
        eng = RiskEngine(assets, events, policy).evaluate()
        agg = eng.aggregate()
        rows = []
        for aid, m in agg.items():
            a = assets.get(aid)
            rows.append({'asset': aid, 'name': a.get('name',''), 'avg': round(m['avg'],2), 'max': round(m['max'],2), 'count': m['count']})
        rows.sort(key=lambda x: (-x['max'], -x['avg']))
        print(fmt_table(rows, ['asset','name','avg','max','count']))
        return
    if cmd == 'filter':
        q = {'type': kv.get('type'), 'label': kv.get('label'), 'asset': kv.get('asset')}
        es = filter_events(events.all(), q)
        print(json.dumps({'count': len(es), 'items': es}, ensure_ascii=False, indent=2))
        return
    if cmd == 'validate':
        errs = []
        if not assets.list_ids():
            errs.append('assets:empty')
        if not events.all():
            errs.append('events:empty')
        if not policy.rules:
            errs.append('policy.rules:empty')
        ok = len(errs) == 0
        print(json.dumps({'ok': ok, 'errors': errs}, ensure_ascii=False))
        return
    if cmd == 'gen':
        out_a = kv.get('assets', 'assets.sample.json')
        out_e = kv.get('events', 'events.sample.json')
        A = {
            'assets': [
                {'id': 'srv-1', 'name': 'srv-1', 'type': 'vm', 'tags': ['prod','pci'], 'criticality': 0.9},
                {'id': 'srv-2', 'name': 'srv-2', 'type': 'vm', 'tags': ['dev'], 'criticality': 0.4},
                {'id': 'db-1', 'name': 'db-1', 'type': 'db', 'tags': ['prod','pii'], 'criticality': 0.95}
            ]
        }
        E = {
            'events': [
                {'id': 'e1', 'ts': now(), 'asset': 'srv-1', 'type': 'alert', 'severity': 0.8, 'labels': ['exfil']},
                {'id': 'e2', 'ts': now(), 'asset': 'db-1', 'type': 'anomaly', 'severity': 0.6, 'labels': ['lateral']},
                {'id': 'e3', 'ts': now(), 'asset': 'srv-2', 'type': 'incident', 'severity': 0.3, 'labels': []}
            ]
        }
        write_json(out_a, A)
        write_json(out_e, E)
        print(out_a)
        print(out_e)
        return
    print('unknown command')

if __name__ == '__main__':
    cli()

print("t.me/Bengamin_Button t.me/XillenAdapter")
