# actors/counter.py
"""VoteCounter — Autorita' di scrutinio (§2.2.4, §2.2.8).

Protezione della capacita' di apertura (§2.2.4 / D2=A): la chiave privata RSA di
scrutinio non e' detenuta in chiaro. Viene incapsulata in una chiave simmetrica
(Fernet/AES, primitiva vista nel lab KDC) e sono le QUOTE di quella chiave a
essere distribuite via Shamir t-su-n ai membri della commissione. Nessun membro,
e nessuna coalizione sotto la soglia, puo' ricostruire la chiave e decifrare. La
ricostruzione avviene solo a urne chiuse.

Scrutinio verificabile (§2.2.8): a urne chiuse VoteCounter decifra ogni scheda,
la classifica nei tre valori ammessi (scartando i fuori-dominio, I.6) e PUBBLICA,
per ogni foglia, la coppia (C, v). Non firma la radice (lo fa VoteCollector alla
chiusura): pubblica i chiari ancorati a quella radice, cosi' che il conteggio sia
ricontabile da chiunque (VU.1).
"""
import logging
import json
from cryptography.hazmat.primitives import serialization
from cryptography.fernet import Fernet

from crypto.pki import PKI
from crypto.shamir import ShamirSecretSharing
from utils.payload import CHOICES
from actors.ca import UnisaCA

logger = logging.getLogger(__name__)

INVALID = "INVALID"  # marcatore per le schede fuori dominio o non decifrabili


class VoteCounter:
    def __init__(self, ca: UnisaCA, threshold: int = 3, shares_count: int = 5, identity: str = "VoteCounter"):
        self.identity = identity
        logger.info(f"Inizializzazione {self.identity} (soglia {threshold}/{shares_count})...")
        self.ca = ca
        self.threshold = threshold
        self.shares_count = shares_count

        # Coppia di chiavi di scrutinio + certificato (la pubblica serve agli elettori per cifrare).
        priv, self.public_key = PKI.generate_rsa_keypair()
        self.cert = ca.issue_certificate(self.identity, self.public_key)

        # Incapsulamento (key-wrapping) della chiave di scrutinio: la privata RSA viene
        # serializzata in PEM e cifrata con una chiave simmetrica Fernet; e' SOLO questa
        # chiave Fernet a essere frammentata con Shamir. Non si applica Shamir alla chiave
        # RSA direttamente perche' il segreto Shamir e' un intero < PRIME (cfr.
        # crypto/shamir.py): un modulo RSA da 2048 bit eccede il campo e, soprattutto, non
        # sarebbe ricostruibile come oggetto-chiave dal solo intero. La chiave Fernet
        # (~352 bit) sta comodamente sotto PRIME, quindi si condivide quella e la si usa
        # per riaprire la privata solo a urne chiuse, con almeno 'threshold' quote (S.3).
        priv_pem = priv.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        )
        fernet_key = Fernet.generate_key()                 # 44 byte base64 (~352 bit)
        self._wrapped_priv = Fernet(fernet_key).encrypt(priv_pem)
        self._key_len = len(fernet_key)
        self.shares = ShamirSecretSharing.split_secret(
            int.from_bytes(fernet_key, "big"), threshold, shares_count
        )
        # Rilascio dei riferimenti al materiale in chiaro: dopo l'incapsulamento la
        # chiave privata di scrutinio, la chiave Fernet e il PEM in chiaro non devono
        # piu' essere raggiungibili dall'oggetto VoteCounter, che da qui in avanti
        # custodisce solo il blob cifrato (self._wrapped_priv) e le quote Shamir. Si
        # noti il limite: in CPython 'del' rimuove il legame del nome e rende l'oggetto
        # candidato alla garbage collection, ma NON e' un azzeramento sicuro della
        # memoria (gli oggetti bytes/int sono immutabili e il loro contenuto puo'
        # restare nelle pagine fino al riuso). Un'erasure garantita richiederebbe
        # buffer mutabili e supporto del runtime/HSM, fuori dal perimetro del corso e
        # rinviata al lavoro futuro (§1.5). Qui l'invariante che conta e' che la chiave
        # di scrutinio non sia ricostruibile sotto la soglia di quote Shamir.
        del priv, fernet_key, priv_pem
        logger.info(f"[{self.identity}] Chiave di scrutinio incapsulata; {shares_count} quote distribuite.")

    def get_shares(self) -> list:
        return self.shares

    def _reconstruct_private_key(self, provided_shares):
        if len(provided_shares) < self.threshold:
            raise PermissionError(
                f"Quote insufficienti: richieste {self.threshold}, fornite {len(provided_shares)}."
            )
        key_int = ShamirSecretSharing.reconstruct_secret(provided_shares)
        fernet_key = key_int.to_bytes(self._key_len, "big")  # lunghezza nota: niente ambiguita'
        priv_pem = Fernet(fernet_key).decrypt(self._wrapped_priv)
        return serialization.load_pem_private_key(priv_pem, password=None)

    def tally(self, public_board: dict, provided_shares: list, expected_election_id: str) -> dict:
        """Scrutinio differito: ricostruisce la chiave, decifra, classifica, pubblica (C, v)."""
        records = public_board["records"]
        logger.info(f"[{self.identity}] Scrutinio di {len(records)} schede...")
        priv = self._reconstruct_private_key(provided_shares)

        scrutiny = []  # list[(seq, C, v)] con v in CHOICES o INVALID
        counts = {c: 0 for c in CHOICES}
        discarded_corrupt = 0
        discarded_domain = 0

        for rec in records:
            C = rec.ciphertext
            try:
                payload = json.loads(PKI.decrypt(priv, C).decode())
            except Exception:
                # decifratura OAEP fallita: ciphertext corrotto (I.6, caso a)
                scrutiny.append((rec.seq, C, INVALID))
                discarded_corrupt += 1
                continue
            if payload.get("election_id") != expected_election_id or payload.get("choice") not in CHOICES:
                # chiaro valido ma fuori dominio / elezione errata (I.6, caso b)
                scrutiny.append((rec.seq, C, INVALID))
                discarded_domain += 1
                continue
            v = payload["choice"]
            counts[v] += 1
            scrutiny.append((rec.seq, C, v))

        valid_total = sum(counts.values())
        logger.info(f"[{self.identity}] Scrutinio terminato. Validi: {valid_total}.")
        # Risultato PUBBLICO: aggregati + coppie (C, v) ancorate alla radice firmata dalla bacheca.
        return {
            "aggregates": counts,                 # {SI, NO, BIANCA}
            "valid_total": valid_total,
            "discarded_corrupt": discarded_corrupt,
            "discarded_domain": discarded_domain,
            "scrutiny": scrutiny,                  # [(seq, C, v)]
            "counter_cert_pem": PKI.cert_to_pem(self.cert),
        }
