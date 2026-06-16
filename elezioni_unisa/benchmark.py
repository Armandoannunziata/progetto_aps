# benchmark.py
"""Sweep prestazionale (WP4 - D9).

Tre blocchi, come richiesto dalla traccia (costo computazionale, dimensione dei
messaggi, latenza delle verifiche):

  1. Micro-benchmark per-operazione (media su ITER ripetizioni): keygen RSA,
     OAEP cifra/decifra, PSS firma/verifica, SHA-256, Shamir split/reconstruct,
     Merkle build/proof/verify.
  2. Dimensione dei messaggi: scheda (C), token, ricevuta (Merkle proof a
     profondita' log2 N).
  3. Sweep di scala su N = {100, 1000, 10000}: tempo di costruzione dell'urna,
     tempo di scrutinio (N decifrature) e latenza della verifica universale.

Nota metodologica: nel blocco 3 si riutilizza un piccolo pool di chiavi effimere
per sintetizzare le N schede; il costo della generazione di chiave e' gia' misurato
a parte (blocco 1). Il riuso non altera i tempi delle operazioni che scalano con N
(cifratura, decifratura, hashing, verifica di firma), ma rende eseguibile N=10000.
La verifica universale a scala viene misurata su una bacheca pubblica REALE
(bulletin_board.PublicBulletin), non su una struttura sintetica parallela: il
verificatore percorre esattamente gli stessi controlli di catena/firma/CRL del
flusso di produzione, e non esiste un secondo modello-dati da tenere allineato.
"""
import time
import json
import hashlib
import statistics

from crypto.pki import PKI
from crypto.shamir import ShamirSecretSharing
from crypto.merkle import MerkleTree
from utils.payload import VotePayload, EncryptedBallot, PublicRecord
from bulletin_board import PublicBulletin
from actors.ca import UnisaCA
from actors.registrar import AuthUnisa
from actors.collector import VoteCollector
from actors.counter import VoteCounter
import verifier

ITER = 50
SIZES = [100, 1000, 10000]
EID = "BENCH"


def timeit(fn, iters):
    samples = []
    for _ in range(iters):
        t = time.perf_counter()
        fn()
        samples.append((time.perf_counter() - t) * 1000.0)  # ms
    return statistics.mean(samples), statistics.pstdev(samples)


def micro_benchmarks():
    print("\n== 1) Micro-benchmark per-operazione (ms, media +/- dev su %d iter) ==" % ITER)
    priv, pub = PKI.generate_rsa_keypair()
    msg = b"x" * 32
    sig = PKI.sign(priv, msg)
    pt = VotePayload(EID, "SI").to_bytes()
    ct = PKI.encrypt(pub, pt)
    shares = ShamirSecretSharing.split_secret(123456789, 3, 5)

    ops = {
        "RSA-2048 keygen": lambda: PKI.generate_rsa_keypair(),
        "OAEP encrypt": lambda: PKI.encrypt(pub, pt),
        "OAEP decrypt": lambda: PKI.decrypt(priv, ct),
        "PSS sign": lambda: PKI.sign(priv, msg),
        "PSS verify": lambda: PKI.verify(pub, msg, sig),
        "SHA-256 (1KB)": lambda: hashlib.sha256(b"y" * 1024).digest(),
        "Shamir split (3/5)": lambda: ShamirSecretSharing.split_secret(123456789, 3, 5),
        "Shamir reconstruct": lambda: ShamirSecretSharing.reconstruct_secret(shares[:3]),
    }
    it = {"RSA-2048 keygen": 10, "Shamir split (3/5)": 1000, "Shamir reconstruct": 1000}
    for name, fn in ops.items():
        m, s = timeit(fn, it.get(name, ITER))
        print(f"  {name:24s} {m:9.4f} +/- {s:.4f}")


def message_sizes():
    print("\n== 2) Dimensione dei messaggi (byte) ==")
    priv, pub = PKI.generate_rsa_keypair()
    eph_priv, eph_pub = PKI.generate_rsa_keypair()
    C = PKI.encrypt(pub, VotePayload(EID, "SI").to_bytes())
    eph_pem = PKI.pub_to_pem(eph_pub)
    auth = PKI.sign(eph_priv, C)
    reg_sig = PKI.sign(priv, b"tok" + eph_pem)
    token_bytes = len(("TK-" + "0" * 32).encode()) + len(eph_pem) + len(reg_sig)
    print(f"  ciphertext scheda C (RSA-2048 OAEP)      : {len(C)}")
    print(f"  firma effimera Auth (RSA-2048 PSS)       : {len(auth)}")
    print(f"  token (id + PK_eff PEM + firma registrar): {token_bytes}")
    for n in SIZES:
        depth = max(1, (n - 1).bit_length())
        # ogni passo di proof: hash esadecimale (64 char) + posizione
        proof_bytes = depth * (64 + 5)
        print(f"  ricevuta (Merkle proof, N={n:<6d} -> prof. {depth:2d}) ~ {proof_bytes} byte")


def _synth_records(n, counter_pub, reg_priv, pool):
    """Sintetizza n record validi riusando un pool di chiavi effimere."""
    records = []
    for i in range(n):
        eph_priv, eph_pub, eph_pem = pool[i % len(pool)]
        C = PKI.encrypt(counter_pub, VotePayload(EID, ["SI", "NO", "BIANCA"][i % 3]).to_bytes())
        token_id = "TK-%032x" % i
        reg_sig = PKI.sign(reg_priv, token_id.encode() + eph_pem)
        auth = PKI.sign(eph_priv, C)
        records.append(PublicRecord(i, C, token_id, eph_pem, reg_sig, auth))
    return records


def scale_sweep():
    print("\n== 3) Sweep di scala N (tempi in ms) ==")
    print(f"  {'N':>7s} | {'urna build':>12s} | {'scrutinio':>12s} | {'verifica univ.':>15s}")
    counter_priv, counter_pub = PKI.generate_rsa_keypair()
    reg_priv, reg_pub = PKI.generate_rsa_keypair()
    pool = [(p, pub, PKI.pub_to_pem(pub)) for (p, pub) in (PKI.generate_rsa_keypair() for _ in range(8))]

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

        # bacheca pubblica REALE per la verifica universale (riusa PublicBulletin)
        scrutiny = []
        agg = {"SI": 0, "NO": 0, "BIANCA": 0}
        for r in records:
            v = ["SI", "NO", "BIANCA"][r.seq % 3]
            agg[v] += 1
            scrutiny.append((r.seq, r.ciphertext, v))
        b = _public_bulletin(records, root, scrutiny, agg, reg_pub, counter_priv)
        t = time.perf_counter()
        verifier.verify_election(b)
        verify_ms = (time.perf_counter() - t) * 1000.0

        print(f"  {n:>7d} | {build_ms:>12.2f} | {tally_ms:>12.2f} | {verify_ms:>15.2f}")


def _public_bulletin(records, root, scrutiny, aggregates, reg_pub, counter_priv):
    """Costruisce una bacheca pubblica REALE (bulletin_board.PublicBulletin) per misurare
    la verifica universale a scala, anziche' re-dichiarare a mano i campi del bundle. Si
    riusa cosi' l'unica struttura pubblica del sistema, eliminando il percorso-dati
    parallelo (la vecchia classe-ombra _BundleStub) che andava mantenuto in sincronia con
    PublicBulletin. I certificati di registrar/collector/counter sono firmati da una CA
    effimera (UnisaCA, ora a 2048 bit come gli altri attori), cosi' che il verificatore
    esegua ESATTAMENTE le stesse verifiche di catena/firma/CRL del flusso reale; la firma
    del registrar sui token usa la coppia reg_pub coerente con reg_cert."""
    from cryptography.hazmat.primitives.serialization import Encoding
    ca = UnisaCA()
    reg_cert = ca.issue_certificate("AuthUnisa", reg_pub)
    col_priv, col_pub = PKI.generate_rsa_keypair()
    col_cert = ca.issue_certificate("VoteCollector", col_pub)
    cnt_cert = ca.issue_certificate("VoteCounter", counter_priv.public_key())
    valid_total = sum(aggregates.values())
    return PublicBulletin(
        election_id=EID,
        electorate_size=len(records),
        records=records,
        root=root,
        signed_root=PKI.sign(col_priv, root.encode()),
        aggregates=aggregates,
        valid_total=valid_total,
        discarded_corrupt=0,
        discarded_domain=len(records) - valid_total,
        scrutiny=scrutiny,
        root_cert_pem=PKI.cert_to_pem(ca.get_root_cert()),
        crl_pem=ca.get_crl().public_bytes(Encoding.PEM),
        registrar_cert_pem=PKI.cert_to_pem(reg_cert),
        collector_cert_pem=PKI.cert_to_pem(col_cert),
        counter_cert_pem=PKI.cert_to_pem(cnt_cert),
    )


if __name__ == "__main__":
    import logging
    logging.disable(logging.INFO)  # output pulito per il benchmark
    micro_benchmarks()
    message_sizes()
    scale_sweep()
