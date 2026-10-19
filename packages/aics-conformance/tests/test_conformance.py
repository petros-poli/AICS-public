"""Every registered check has both an actual passing and wire-fault failing case."""
import json
import pytest
from aics_conformance import checks, guarantees
from aics_conformance.core import CHECKS
from aics_conformance.fakes import FakeServer

@pytest.mark.parametrize('check',CHECKS,ids=lambda c:c.id)
def test_conforming_server(check):
    result=check.run(FakeServer().context())
    assert set(result)=={'id','title','spec_ref','verdict','details'}
    assert result['verdict']=='pass',result['details'].get('reason')
    json.dumps(result)

@pytest.mark.parametrize('check',CHECKS,ids=lambda c:c.id)
def test_detects_wire_fault(check):
    result=check.run(FakeServer(check.fault).context())
    assert result['verdict']=='fail',(check.id,check.fault,result)
    assert 'trust_bundle' in result['details']['evidence']
    json.dumps(result)


def test_unique_ids_and_ten_guarantee_modules():
    assert len({c.id for c in CHECKS})==len(CHECKS)
    for i in range(1,11):
        c=next(c for c in CHECKS if c.id==f'G{i}')
        assert c.function.__module__.endswith(f'.g{i}')
