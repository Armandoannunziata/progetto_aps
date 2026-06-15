# verifier.py
"""Verificatore universale (§2.2.8 — VU.1, VU.2, VU.3, I.5, I.6, I.7).

Funzione eseguibile da CHIUNQUE a partire dai soli dati pubblici (PublicBulletin).
Non si fida degli attori: ricarica i certificati e li verifica fino alla radice di
UnisaCA, controlla la CRL, ricostruisce l'urna dai record e ne ricalcola la radice,
verifica le autorizzazioni e il legame token<->scheda, riconta i chiari e calcola
il quorum. Tutte le verifiche sono deterministiche (VU.3).

Limite dichiarato (§2.2.8): il verificatore NON puo' accertare che il chiaro v sia
la decifrazione onesta del ciphertext C (manca la decifrazione verificabile, fuori
dal corso). Verifica la corrispondenza urna<->ciphertext e la correttezza aritmetica
del conteggio; la fedelta' della singola decifrazione cede solo sotto collusione
dell'intera soglia di VoteCounter, come gia' dichiarato in §1.5.
"""
import logging
from cryptography.x509 import load_pem_x509_crl

from crypto.pki import PKI
from crypto.merkle import MerkleTree
from utils.payload import CHOICES

logger = logging.getLogger(__name__)
INVALID = "INVALID"


def _check(report, key, ok, detail=""):
    report[key] = {"ok": bool(ok), "detail": detail}
    return ok


def verify_election(b) -> dict:
    """Esegue tutte le verifiche pubbliche. Ritorna un report con esito complessivo."""
    report = {}
    overall = True

    # 0. Ancore di fiducia: carica radice, CRL e i certificati delle autorita'; verifica catena + revoca.
    root_cert = PKI.cert_from_pem(b.root_cert_pem)
    crl = load_pem_x509_crl(b.crl_pem)
    certs = {}
    try:
        for name, pem in (("registrar", b.registrar_cert_pem),
                          ("collector", b.collector_cert_pem),
                          ("counter", b.counter_cert_pem)):
            c = PKI.cert_from_pem(pem)
            PKI.verify_chain(c, root_cert)
            if PKI.is_revoked(c, crl):
                raise ValueError(f"certificato {name} revocato")
            certs[name] = c
        overall &= _check(report, "trust_anchors", True, "certificati delle autorita' validi e non revocati")
    except (ValueError, PermissionError) as e:
        overall &= _check(report, "trust_anchors", False, str(e))
        return {"passed": overall, "checks": report}  # senza fiducia non si prosegue

    reg_pub = certs["registrar"].public_key()
    col_pub = certs["collector"].public_key()

    # 1. Autenticita' della radice: firma di VoteCollector sulla radice (I.1).
    overall &= _check(report, "signed_root",
                      PKI.verify(col_pub, b.root.encode(), b.signed_root),
                      "radice firmata da VoteCollector")

    # 2. Integrita' dell'urna: ricostruzione della radice dai record pubblici (VU.1, VU.3).
    rebuilt = MerkleTree.from_leaves([r.leaf_data() for r in b.records]).get_root()
    overall &= _check(report, "urn_root_match", rebuilt == b.root,
                      "radice ricostruita dai record == radice pubblicata")

    # 3. Autorizzazioni e legame (VU.2 + D1): ogni foglia ha un token valido, niente duplicati.
    seen = set()
    auth_ok = True
    dup_ok = True
    for r in b.records:
        token = r.to_token()
        if not PKI.verify(reg_pub, token.signed_payload(), r.registrar_signature):
            auth_ok = False
        eph_pub = PKI.pub_from_pem(r.ephemeral_pub_key_pem)
        if not PKI.verify(eph_pub, r.ciphertext, r.ephemeral_signature):
            auth_ok = False
        if r.token_id in seen:
            dup_ok = False
        seen.add(r.token_id)
    overall &= _check(report, "authorizations_valid", auth_ok,
                      "ogni scheda reca un token firmato da AuthUnisa e legato al ciphertext")
    overall &= _check(report, "no_duplicate_tokens", dup_ok, "nessun token duplicato nell'urna")

    # 4. Riconteggio (I.5, I.6): i chiari (C, v) si riferiscono alle foglie e tornano con gli aggregati.
    by_seq = {r.seq: r.ciphertext for r in b.records}
    counts = {c: 0 for c in CHOICES}
    disc = 0
    corr_ref = True
    for seq, C, v in b.scrutiny:
        if by_seq.get(seq) != C:           # il chiaro deve riferirsi al ciphertext realmente in urna
            corr_ref = False
        if v in CHOICES:
            counts[v] += 1
        else:
            disc += 1
    overall &= _check(report, "scrutiny_refers_urn", corr_ref,
                      "ogni coppia (C, v) si riferisce a un ciphertext presente in urna")
    overall &= _check(report, "recount_matches", counts == b.aggregates,
                      f"riconteggio {counts} == aggregati pubblicati {b.aggregates}")
    overall &= _check(report, "discarded_matches",
                      disc == (b.discarded_corrupt + b.discarded_domain),
                      "numero di scarti coerente con quanto pubblicato")
    overall &= _check(report, "total_consistent",
                      sum(counts.values()) + disc == len(b.records),
                      "validi + scartati == numero di foglie")

    # 5. Quorum (I.7): 50%+1 degli aventi diritto. Le bianche contano tra i validi.
    threshold = b.electorate_size // 2 + 1
    valid_total = sum(counts.values())
    reached = valid_total >= threshold
    _check(report, "quorum", True,
           f"validi={valid_total}, soglia(50%+1)={threshold}, quorum {'RAGGIUNTO' if reached else 'NON raggiunto'}")
    report["quorum_reached"] = reached

    report["residual_limit"] = {
        "ok": True,
        "detail": "la fedelta' della decifrazione (v == Dec(C)) non e' verificabile dall'esterno; "
                  "cede solo sotto collusione dell'intera soglia di VoteCounter (cfr. §1.5).",
    }
    return {"passed": overall, "quorum_reached": reached, "checks": report}


def print_report(result: dict) -> None:
    print(f"\nEsito verifica universale: {'PASS' if result['passed'] else 'FAIL'}")
    for k, v in result["checks"].items():
        if isinstance(v, dict) and "ok" in v:
            mark = "OK " if v["ok"] else "NO "
            print(f"  [{mark}] {k}: {v['detail']}")
