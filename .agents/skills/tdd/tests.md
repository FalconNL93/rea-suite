# Good and bad tests

## Good tests

**Through real interfaces**, not fakes of internal parts.

```python
# GOOD: observable behavior, waited for by an event, the three outcomes from the test kit
def main():
    with Session("ban") as s:
        server = s.launch(dedicated=True)
        player = s.launch(key=BANNED_KEY)
        player.connect(server)
        line = player.wait_log(r"You are banned", timeout=20, what="the refusal")
        if server.wait(lambda st: st.players, timeout=5, what="the player list") != []:
            raise TestFailure(f"the banned player joined ({line})")

run_test(main)
```

Characteristics:

- it tests what a player or caller sees;
- it uses the public interface only;
- it survives internal refactors;
- its name says WHAT, not HOW;
- one logical assertion per test.

## Bad tests

**Implementation details**: coupled to internal structure.

```python
# BAD: checks how, not what
def test_join_calls_ban_list_lookup(monkeypatch):
    calls = []
    monkeypatch.setattr(bans, "lookup", lambda key: calls.append(key))
    server.on_connect(packet)
    assert calls == [packet.key]
```

Red flags:

- faking internal collaborators;
- testing private functions;
- asserting on call counts or order;
- breaking on a refactor without a behavior change;
- a name that describes HOW, not WHAT;
- verifying through other means than the interface (a database row, guest memory);
- a fixed sleep instead of an event.

```python
# BAD: bypasses the interface to verify
def test_ban_saves_row(db):
    ban(KEY)
    assert db.execute("SELECT 1 FROM bans WHERE key = ?", (KEY,)).fetchone()

# GOOD: verifies through the interface
def test_a_banned_key_is_refused():
    ban(KEY)
    assert join(KEY).refused
```

**Tautological tests**: the expected value restates the implementation, so the test passes by
construction.

```python
# BAD: the expected value is computed the way the code computes it
def test_checksum():
    data = b"\x01\x02\x03"
    assert checksum(data) == sum(data) & 0xFF

# GOOD: an independent, known value (recorded from the original game)
def test_checksum():
    assert checksum(b"\x01\x02\x03") == 0x06
```
