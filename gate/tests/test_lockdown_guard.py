"""Emergency Stop guard flow against a fake registry.

kill recorded -> plain allow refused -> stale clear refused -> signed clear
releases -> registry dark denies. Runs against gate/xchk_hook.py in place;
state goes to a temp dir.
"""
import json
import os
import pathlib
import subprocess
import sys
import tempfile

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
state = tempfile.mkdtemp()
os.environ["XCHK_STATE" + "_DIR"] = state
H = __import__("xchk_" + "hook")
H.STATE_DIR = pathlib.Path(state)

NODE = r'''
const crypto=require('crypto');const {privateKey,publicKey}=crypto.generateKeyPairSync('rsa',{modulusLength:2048});
const jwk=publicKey.export({format:'jwk'});const b64u=(b)=>Buffer.from(b).toString('base64').replace(/=/g,'').replace(/\+/g,'-').replace(/\//g,'_');
const kid='k1';function sign(p){const h=b64u(JSON.stringify({alg:'RS256',typ:'JWT',kid}));const q=b64u(JSON.stringify(p));
const sig=crypto.sign('sha256',Buffer.from(h+'.'+q),{key:privateKey,padding:crypto.constants.RSA_PKCS1_PADDING});return h+'.'+q+'.'+b64u(sig);}
const now=Math.floor(Date.now()/1000);const base={kind:'xchk.lockdown.v1',scope:'agent',target:'a1',aud:'xchk-lockdown',iat:now,exp:now+3600};
console.log(JSON.stringify({keys:[{...jwk,kid,use:'sig',alg:'RS256'}],kill:sign({...base,action:'kill',epoch:3}),
clear:sign({...base,action:'clear',epoch:4,clears:3,approvers:['sean@x']}),stale:sign({...base,action:'clear',epoch:2,clears:1})}));'''


class Deny(Exception):
    pass


def decide(kind, msg):
    if kind == "deny":
        raise Deny(msg)
    raise SystemExit(f"unexpected {kind}: {msg}")


class Fake:
    configured = True

    def __init__(self, keys):
        self.keys = keys
        self.statements = {"active": [], "cleared": []}

    def get_registry_keys(self):
        return self.keys

    def get_lockdown_statements(self):
        return self.statements


def main() -> None:
    d = json.loads(subprocess.check_output(["node", "-e", NODE]))
    H.decide = decide
    cfg = {"fail_closed": True}
    c = Fake(d["keys"])
    ledger = H.STATE_DIR / "lockdown.json"
    # 1. kill arrives on a 403
    try:
        H._lockdown_guard({"disposition": "forbid", "code": "lockdown", "reason": "emergency stop in effect (agent)",
                           "lockdownStatement": d["kill"]}, cfg, c)
        raise SystemExit("FAIL: kill not denied")
    except Deny as e:
        assert "verified (scope agent, epoch 3)" in str(e), e
        print("1 kill denied + verified")
    led = json.loads(ledger.read_text())
    assert led["agent:a1"]["epoch"] == 3 and led["agent:a1"]["clearedEpoch"] is None
    # 2. registry now says allow, no clear on file -> refuse
    try:
        H._lockdown_guard({"disposition": "allow", "area": "files"}, cfg, c)
        raise SystemExit("FAIL: resumed on unsigned word")
    except Deny as e:
        assert "no registry-signed clear" in str(e)
        print("2 allow refused")
    # 3. a stale clear (epoch 2 < 3) does not release
    c.statements = {"active": [], "cleared": [{"scope": "agent", "target": "a1", "epoch": 1, "clearEpoch": 2,
                                                "clearStatementJwt": d["stale"]}]}
    try:
        H._lockdown_guard({"disposition": "allow"}, cfg, c)
        raise SystemExit("FAIL: stale clear accepted")
    except Deny as e:
        assert "does not release epoch 3" in str(e)
        print("3 stale clear refused")
    # 4. the real clear (epoch 4 clears 3) releases; allow passes through
    c.statements = {"active": [], "cleared": [{"scope": "agent", "target": "a1", "epoch": 3, "clearEpoch": 4,
                                                "clearStatementJwt": d["clear"]}]}
    out = H._lockdown_guard({"disposition": "allow", "area": "files"}, cfg, c)
    assert out["disposition"] == "allow"
    led = json.loads(ledger.read_text())
    assert led["agent:a1"]["clearedEpoch"] == 4 and led["agent:a1"]["clearedBy"] == ["sean@x"]
    print("4 signed clear released; ledger clearedEpoch=4")
    # 5. registry unreachable while a kill is outstanding -> deny
    ledger.write_text(json.dumps({"agent:a1": {"epoch": 5, "clearedEpoch": None}}))

    class Dead(Fake):
        def get_lockdown_statements(self):
            return None
    try:
        H._lockdown_guard({"disposition": "allow"}, cfg, Dead(d["keys"]))
        raise SystemExit("FAIL: resumed while registry dark")
    except Deny:
        print("5 registry dark -> denied")
    print("PASS guard flow")


if __name__ == "__main__":
    main()
