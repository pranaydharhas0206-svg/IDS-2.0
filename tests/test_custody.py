from toolkit.core.custody import ChainOfCustody


def test_chain_verifies_after_normal_use(tmp_path):
    c = ChainOfCustody(tmp_path)
    c.record("case_opened", actor="examiner1", detail="opened")
    c.record("acquired", actor="examiner1", detail="acquired evidence X", evidence_id="ev1")
    c.record("analyzed", actor="examiner1", detail="parsed evidence X", evidence_id="ev1")

    ok, broken_seq = c.verify_chain()
    assert ok is True
    assert broken_seq is None


def test_chain_persists_across_reload(tmp_path):
    c1 = ChainOfCustody(tmp_path)
    c1.record("case_opened", actor="examiner1", detail="opened")
    c1.record("acquired", actor="examiner1", detail="acquired evidence X", evidence_id="ev1")

    c2 = ChainOfCustody(tmp_path)
    assert len(c2.entries) == 2
    ok, _ = c2.verify_chain()
    assert ok is True


def test_chain_detects_tampering(tmp_path):
    c = ChainOfCustody(tmp_path)
    c.record("case_opened", actor="examiner1", detail="opened")
    c.record("acquired", actor="examiner1", detail="acquired evidence X", evidence_id="ev1")

    # Simulate an attacker editing the on-disk log after the fact.
    c.entries[0].detail = "opened by someone else"

    ok, broken_seq = c.verify_chain()
    assert ok is False
    assert broken_seq == 0
