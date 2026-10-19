import json
from aics_conformance.cli import main
from aics_conformance.core import CHECKS

def test_list(capsys):
    assert main(['list','--json'])==0
    rows=json.loads(capsys.readouterr().out)
    assert len(rows)==len(CHECKS)

def test_selftest(tmp_path):
    path=tmp_path/'selftest.json'
    assert main(['selftest','--mutations','--report',str(path)])==0
    report=json.loads(path.read_text())
    assert report['counts']=={'pass':len(CHECKS),'fail':0,'skip':0}
    assert all(m['detected'] for m in report['mutations'])
