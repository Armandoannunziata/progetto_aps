# performance.py
"""Valutazione prestazionale completa del prototipo (WP4 - D9).

Copre i quattro aspetti di prestazione richiesti dalla traccia:

  1) COSTO COMPUTAZIONALE delle operazioni crittografiche (per-operazione, in ms);
  2) DIMENSIONE DEI MESSAGGI scambiati (scheda, token, firma, ricevuta), in byte;
  3) LATENZA DELLE VERIFICHE: verifica universale a scala N (e sue componenti);
  4) TEMPI DI INTERAZIONE dei protocolli a piu' passi: autenticazione
     challenge-response + rilascio del token, sessione di voto end-to-end,
     verifica individuale della ricevuta.

I primi tre blocchi riusano gli helper gia' presenti in benchmark.py (timeit,
_synth_records, _public_bulletin) per non duplicarne la logica di misura; questo
modulo li orchestra raccogliendo i risultati in strutture dati, li stampa in un
report ordinato e, con --json, li salva su file (dataset della relazione).

Il blocco 4 misura SOLO percorsi reali degli attori (Voter.cast_vote,
AuthUnisa.issue_challenge/request_voting_token, Voter.verify_receipt): nessuna
messinscena, gli stessi metodi del flusso di produzione. Vale la Regola d'Oro:
sola libreria cryptography, solo primitive del corso.
"""
import sys
import time
import json
import hashlib
import platform
import logging
import statistics

from crypto.pki import PKI
from crypto.shamir import ShamirSecretSharing
from crypto.merkle import MerkleTree
from utils.payload import VotePayload
import verifier

# Riuso degli helper di misura gia' validati nel benchmark (niente duplicazione).
from benchmark import timeit, _synth_records, _public_bulletin, ITER, SIZES, EID

# Attori reali per il blocco dei tempi di interazione.
from actors.ca import UnisaCA
from actors.registrar import AuthUnisa
from actors.collector import VoteCollector
from actors.counter import VoteCounter
from scenarios import Env, make_voter, ELECTION_ID

# Ripetizioni del blocco interattivo: ogni elettore consuma un solo token (U.1),
# quindi servono identita' distinte; un valore moderato basta a stimare la media.
INTER_REPS = 25


# --------------------------------------------------------------------------- #
# Blocco 1 - costo computazionale delle operazioni crittografiche
# --------------------------------------------------------------------------- #
def measure_crypto_costs():
    priv, pub = PKI.generate_rsa_keypair()
    msg = b"x" * 32
    sig = PKI.sign(priv, msg)
    pt = VotePayload(EID, "SI").to_bytes()
    ct = PKI.encrypt(pub, pt)
    shares = ShamirSecretSharing.split_secret(123456789, 3, 5)

    ops = {
        "RSA-2048 keygen": lambda: PKI.generate_rsa_keypair(),
        "OAEP encrypt (voto)": lambda: PKI.encrypt(pub, pt),
        "OAEP decrypt (scrutinio)": lambda: PKI.decrypt(priv, ct),
        "PSS sign": lambda: PKI.sign(priv, msg),
        "PSS verify": lambda: PKI.verify(pub, msg, sig),
        "SHA-256 (1KB)": lambda: hashlib.sha256(b"y" * 1024).digest(),
        "Shamir split (3/5)": lambda: ShamirSecretSharing.split_secret(123456789, 3, 5),
        "Shamir reconstruct (3)": lambda: ShamirSecretSharing.reconstruct_secret(shares[:3]),
    }
    # iterazioni differenziate: poche per il keygen (costoso), molte per Shamir (rapido).
    iters = {"RSA-2048 keygen": 10, "Shamir split (3/5)": 1000, "Shamir reconstruct (3)": 1000}
    return [(name, *timeit(fn, iters.get(name, ITER))) for name, fn in ops.items()]


# --------------------------------------------------------------------------- #
# Blocco 2 - dimensione dei messaggi scambiati
# --------------------------------------------------------------------------- #
def measure_message_sizes():
    priv, pub = PKI.generate_rsa_keypair()
    eph_priv, eph_pub = PKI.generate_rsa_keypair()
    C = PKI.encrypt(pub, VotePayload(EID, "SI").to_bytes())
    eph_pem = PKI.pub_to_pem(eph_pub)
    auth = PKI.sign(eph_priv, C)
    reg_sig = PKI.sign(priv, b"tok" + eph_pem)
    token_bytes = len(("TK-" + "0" * 32).encode()) + len(eph_pem) + len(reg_sig)

    sizes = {
        "ciphertext scheda C (RSA-2048 OAEP)": len(C),
        "firma effimera su C (RSA-2048 PSS)": len(auth),
        "chiave effimera PK_eff (PEM)": len(eph_pem),
        "token (id + PK_eff + firma registrar)": token_bytes,
    }
    receipts = []
    for n in SIZES:
        depth = max(1, (n - 1).bit_length())
        proof_bytes = depth * (64 + 5)  # per livello: hash esadecimale (64) + posizione
        receipts.append((n, depth, proof_bytes))
    return sizes, receipts


# --------------------------------------------------------------------------- #
# Blocco 3 - latenza delle verifiche a scala N
# --------------------------------------------------------------------------- #
def measure_scale():
    counter_priv, counter_pub = PKI.generate_rsa_keypair()
    reg_priv, reg_pub = PKI.generate_rsa_keypair()
    pool = [(p, pub, PKI.pub_to_pem(pub))
            for (p, pub) in (PKI.generate_rsa_keypair() for _ in range(8))]

    rows = []
    for n in SIZES:
        records = _synth_records(n, counter_pub, reg_priv, pool)

        t = time.perf_counter()
        tree = MerkleTree.from_leaves([r.leaf_data() for r in records])
        root = tree.get_root()
        build_ms = (time.perf_counter() - t) * 1000.0

        t = time.perf_counter()
        for r in records:
            try:
                json.loads(PKI.decrypt(counter_priv, r.ciphertext).decode())
            except Exception:
                pass
        tally_ms = (time.perf_counter() - t) * 1000.0

        scrutiny, agg = [], {"SI": 0, "NO": 0, "BIANCA": 0}
        for r in records:
            v = ["SI", "NO", "BIANCA"][r.seq % 3]
            agg[v] += 1
            scrutiny.append((r.seq, r.ciphertext, v))
        b = _public_bulletin(records, root, scrutiny, agg, reg_pub, counter_priv)

        t = time.perf_counter()
        verifier.verify_election(b)
        verify_ms = (time.perf_counter() - t) * 1000.0

        rows.append((n, build_ms, tally_ms, verify_ms))
    return rows


# --------------------------------------------------------------------------- #
# Blocco 4 - tempi di interazione dei protocolli (percorsi reali degli attori)
# --------------------------------------------------------------------------- #
def _interaction_env(reps):
    """Ambiente con 2*reps aventi diritto: un gruppo per la sessione di voto
    completa, l'altro per l'autenticazione + rilascio token isolata (ogni
    identita' puo' ottenere un solo token, U.1)."""
    ca = UnisaCA()
    cast_ids = ["0512%06d" % i for i in range(reps)]
    auth_ids = ["0513%06d" % i for i in range(reps)]
    registrar = AuthUnisa(ca, cast_ids + auth_ids)
    counter = VoteCounter(ca, threshold=3, shares_count=5)
    collector = VoteCollector(ca, registrar.cert)
    env = Env(ca, registrar, collector, counter, counter.cert)
    return env, cast_ids, auth_ids


def measure_interaction(reps=INTER_REPS):
    env, cast_ids, auth_ids = _interaction_env(reps)

    # (a) Sessione di voto END-TO-END: l'intero cast_vote (challenge-response,
    #     keygen effimero, richiesta token, cifratura, firma, sottomissione).
    cast_voters = [make_voter(env, vid) for vid in cast_ids]
    cast_samples = []
    for v in cast_voters:
        t = time.perf_counter()
        v.cast_vote(ELECTION_ID, "SI")
        cast_samples.append((time.perf_counter() - t) * 1000.0)

    # (b) AUTENTICAZIONE + RILASCIO TOKEN isolati: il round-trip di protocollo,
    #     con la chiave effimera pre-generata fuori dalla misura per non includere
    #     il keygen (gia' quotato nel blocco 1).
    auth_voters = [make_voter(env, vid) for vid in auth_ids]
    eph = [PKI.pub_to_pem(PKI.generate_rsa_keypair()[1]) for _ in auth_ids]
    auth_samples = []
    for v, eph_pem in zip(auth_voters, eph):
        t = time.perf_counter()
        nonce = env.registrar.issue_challenge(v.voter_id)
        signed = PKI.sign(v.personal_private_key, nonce)
        env.registrar.request_voting_token(v.voter_id, v.personal_cert, signed, eph_pem)
        auth_samples.append((time.perf_counter() - t) * 1000.0)

    # (c) VERIFICA INDIVIDUALE della ricevuta (a urne chiuse): Merkle proof +
    #     verifica della firma sulla radice. Richiede l'urna congelata.
    env.collector.close()
    recv_samples = []
    for v in cast_voters:
        t = time.perf_counter()
        v.fetch_receipt()
        v.verify_receipt()
        recv_samples.append((time.perf_counter() - t) * 1000.0)
        v.receipt = None  # forza il re-fetch reale alla misura successiva

    return {
        "reps": reps,
        "cast_end_to_end": (statistics.mean(cast_samples), statistics.pstdev(cast_samples)),
        "auth_token": (statistics.mean(auth_samples), statistics.pstdev(auth_samples)),
        "verify_receipt": (statistics.mean(recv_samples), statistics.pstdev(recv_samples)),
    }


# --------------------------------------------------------------------------- #
# Report
# --------------------------------------------------------------------------- #
def run_all():
    return {
        "machine": {
            "python": platform.python_version(),
            "platform": platform.platform(),
            "processor": platform.processor() or "n/d",
        },
        "iter": ITER,
        "sizes": SIZES,
        "crypto": measure_crypto_costs(),
        "message_sizes": measure_message_sizes(),
        "scale": measure_scale(),
        "interaction": measure_interaction(),
    }


def print_report(R):
    m = R["machine"]
    print("=" * 74)
    print(" VALUTAZIONE PRESTAZIONALE - VoteUnisa (WP4)")
    print(f" Python {m['python']} | {m['platform']}")
    print("=" * 74)

    print(f"\n[1] Costo delle operazioni crittografiche (ms, media +/- dev, {R['iter']} iter)")
    for name, mean, sd in R["crypto"]:
        print(f"    {name:30s} {mean:10.4f} +/- {sd:.4f}")

    print("\n[2] Dimensione dei messaggi (byte)")
    sizes, receipts = R["message_sizes"]
    for name, val in sizes.items():
        print(f"    {name:40s} {val:8d}")
    for n, depth, pb in receipts:
        print(f"    ricevuta Merkle proof (N={n:<6d}, profondita' {depth:2d}) ~ {pb:6d}")

    print("\n[3] Latenza a scala N (ms): costruzione urna | scrutinio | verifica universale")
    print(f"    {'N':>7s} | {'urna build':>12s} | {'scrutinio':>12s} | {'verifica univ.':>15s}")
    for n, build, tally, verify in R["scale"]:
        print(f"    {n:>7d} | {build:>12.2f} | {tally:>12.2f} | {verify:>15.2f}")

    print(f"\n[4] Tempi di interazione (ms, media +/- dev su {R['interaction']['reps']} sessioni)")
    I = R["interaction"]
    for label, key in [("sessione di voto end-to-end", "cast_end_to_end"),
                       ("autenticazione + rilascio token", "auth_token"),
                       ("verifica individuale ricevuta", "verify_receipt")]:
        mean, sd = I[key]
        print(f"    {label:34s} {mean:10.4f} +/- {sd:.4f}")
    print("=" * 74)


if __name__ == "__main__":
    logging.disable(logging.INFO)  # output pulito: si tengono solo gli ERROR
    R = run_all()
    print_report(R)
    if "--json" in sys.argv:
        with open("performance_results.json", "w", encoding="utf-8") as f:
            json.dump(R, f, ensure_ascii=False, indent=2)
        print("\nRisultati salvati in performance_results.json")
