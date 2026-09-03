"""Registry-signed lockdown statements verify on the host — and forgeries don't.

Generates a fresh RSA key with node (present on every dev box), signs
statements the way the registry's oidcJwt.signJwt does (RS256, PKCS#1 v1.5),
and verifies with the gate's stdlib verifier.
"""
import base64
import json
import os
import subprocess
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
from xchk_client import verify_registry_jwt, _b64u_decode  # noqa: E402

NODE = r'''
const crypto=require('crypto');
const {privateKey,publicKey}=crypto.generateKeyPairSync('rsa',{modulusLength:2048});
const jwk=publicKey.export({format:'jwk'});
const b64u=(b)=>Buffer.from(b).toString('base64').replace(/=/g,'').replace(/\+/g,'-').replace(/\//g,'_');
const kid=b64u(crypto.createHash('sha256').update(JSON.stringify({e:jwk.e,kty:jwk.kty,n:jwk.n})).digest());
function sign(payload){const h=b64u(JSON.stringify({alg:'RS256',typ:'JWT',kid}));const p=b64u(JSON.stringify(payload));
 const sig=crypto.sign('sha256',Buffer.from(h+'.'+p),{key:privateKey,padding:crypto.constants.RSA_PKCS1_PADDING});return h+'.'+p+'.'+b64u(sig);}
const now=Math.floor(Date.now()/1000);
const base={kind:'xchk.lockdown.v1',scope:'agent',target:'a1',iss:'in.xchk.io',aud:'xchk-lockdown',iat:now,exp:now+3600};
console.log(JSON.stringify({keys:[{...jwk,kid,use:'sig',alg:'RS256'}],
 kill:sign({...base,action:'kill',epoch:3,active:true}),
 clear:sign({...base,action:'clear',epoch:4,clears:3,active:false,approvers:['sean@x']}),
 expired:sign({...base,action:'kill',epoch:5,exp:now-10}),
 wrongaud:sign({...base,action:'kill',epoch:6,aud:'other'})}));
'''


def main() -> None:
    d = json.loads(subprocess.check_output(["node", "-e", NODE]))
    keys = d["keys"]
    p = verify_registry_jwt(d["kill"], keys, "xchk-lockdown", kind="xchk.lockdown.v1")
    assert p["action"] == "kill" and p["epoch"] == 3, p
    c = verify_registry_jwt(d["clear"], keys, "xchk-lockdown", kind="xchk.lockdown.v1")
    assert c["action"] == "clear" and c["epoch"] == 4 and c["clears"] == 3, c
    h, pl, s = d["kill"].split(".")
    raw = json.loads(_b64u_decode(pl)); raw["epoch"] = 99
    pl2 = base64.urlsafe_b64encode(json.dumps(raw).encode()).decode().rstrip("=")
    for bad, why in [(f"{h}.{pl2}.{s}", "tampered"), (d["expired"], "expired"),
                     (d["wrongaud"], "wrong aud"), ("a.b", "malformed")]:
        try:
            verify_registry_jwt(bad, keys, "xchk-lockdown", kind="xchk.lockdown.v1")
            raise SystemExit(f"FAIL: {why} accepted")
        except ValueError as e:
            print(f"rejected {why}: {e}")
    try:
        verify_registry_jwt(d["kill"], [{**keys[0], "n": keys[0]["n"][:-4] + "AAAA"}], "xchk-lockdown")
        raise SystemExit("FAIL: wrong key accepted")
    except ValueError as e:
        print("rejected wrong key:", e)
    print("PASS: kill + clear verify; tampered/expired/aud/malformed/wrong-key rejected")


if __name__ == "__main__":
    main()
