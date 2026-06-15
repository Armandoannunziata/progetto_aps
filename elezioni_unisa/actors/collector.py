# actors/collector.py
"""VoteCollector — Autorita' di raccolta / urna pubblica (§2.2.2, §2.2.6, §2.2.8).

All'arrivo di una scheda verifica, nell'ordine:
  1. coerenza token_id scheda/token;
  2. non-riuso del token (registro degli spesi, U.2 / The Double);
  3. autenticita' del token: firma di AuthUnisa su (token_id || PK_eff), con la
     chiave pubblica di AuthUnisa ottenuta da un certificato verificato fino a
     UnisaCA in hard-fail (A.3);
  4. legame token<->ciphertext: firma effimera su C verificata con la PK_eff del
     token (D1=A, anti-transfer / anti-MITM).
Se tutto e' valido, registra la scheda come foglia del Merkle tree e la conserva.

La ricevuta (Merkle proof) NON viene emessa alla sottomissione: l'urna e'
append-only e viene CONGELATA alla chiusura (close), quando si costruisce
l'albero e si FIRMA la radice (§2.2.8). Solo allora si emettono proof contro la
radice definitiva. La bacheca pubblica (PublicRecord per ogni foglia) e' esposta
per la verifica universale (VU.1, VU.2).
"""
import logging
from crypto.pki import PKI
from crypto.merkle import MerkleTree
from utils.payload import EncryptedBallot, AuthToken, PublicRecord
from actors.ca import UnisaCA

logger = logging.getLogger(__name__)


class VoteCollector:
    def __init__(self, ca: UnisaCA, registrar_cert, identity: str = "VoteCollector"):
        self.identity = identity
        logger.info(f"Inizializzazione {self.identity}...")
        self.ca = ca
        self.private_key, self.public_key = PKI.generate_rsa_keypair()
        self.cert = ca.issue_certificate(self.identity, self.public_key)

        # Certificato di AuthUnisa, verificato una volta alla configurazione (catena + revoca).
        self.ca.verify_certificate(registrar_cert)
        self._registrar_pub = registrar_cert.public_key()

        self.tree = MerkleTree()
        self.records = []            # list[PublicRecord], in ordine di registrazione
        self.spent_tokens = set()    # token_id gia' consumati (U.2)
        self._closed = False
        self.signed_root = None      # firma PSS della radice, prodotta alla chiusura

    def submit_ballot(self, ballot: EncryptedBallot, token: AuthToken) -> dict:
        if self._closed:
            raise RuntimeError("Urne chiuse: nessuna nuova scheda accettata.")

        # 1. coerenza token/scheda
        if ballot.token_id != token.token_id:
            raise ValueError("token_id della scheda diverso da quello del token.")

        # 2. non-riuso (U.2)
        if ballot.token_id in self.spent_tokens:
            raise ValueError("Token gia' utilizzato (double spending).")

        # 3. autenticita' del token (A.3)
        if not PKI.verify(self._registrar_pub, token.signed_payload(), token.registrar_signature):
            raise ValueError("Firma di AuthUnisa sul token non valida (token contraffatto).")

        # 4. legame token<->ciphertext (D1=A)
        ephemeral_pub = PKI.pub_from_pem(token.voter_ephemeral_pub_key_pem)
        if not PKI.verify(ephemeral_pub, ballot.ciphertext, ballot.ephemeral_signature):
            raise ValueError("Firma effimera sulla scheda non valida (scheda non legata al token).")

        # accettazione
        self.spent_tokens.add(ballot.token_id)
        seq = len(self.records)
        record = PublicRecord(
            seq=seq,
            ciphertext=ballot.ciphertext,
            token_id=token.token_id,
            ephemeral_pub_key_pem=token.voter_ephemeral_pub_key_pem,
            registrar_signature=token.registrar_signature,
            ephemeral_signature=ballot.ephemeral_signature,
        )
        self.records.append(record)
        self.tree.add_leaf(record.leaf_data())
        logger.info(f"[{self.identity}] Scheda accettata (seq={seq}).")
        # alla sottomissione si restituisce solo la posizione: la ricevuta verra' dopo la chiusura
        return {"status": "accepted", "seq": seq}

    def close(self):
        """Chiude le urne: costruisce l'albero, FIRMA la radice (§2.2.8)."""
        if self._closed:
            return
        self.tree.build()
        root = self.tree.get_root()
        self.signed_root = PKI.sign(self.private_key, root.encode()) if root else b""
        self._closed = True
        logger.info(f"[{self.identity}] Urne chiuse. Radice firmata. Foglie: {len(self.records)}.")

    def get_root(self) -> str:
        return self.tree.get_root()

    def get_receipt(self, seq: int) -> dict:
        """Ricevuta dell'elettore (dopo la chiusura): Merkle proof contro la radice definitiva."""
        if not self._closed:
            raise RuntimeError("Ricevute disponibili solo a urne chiuse.")
        return {
            "leaf_data": self.records[seq].leaf_data(),
            "proof": self.tree.get_proof(seq),
            "root": self.tree.get_root(),
            "signed_root": self.signed_root,
        }

    # --- bacheca pubblica (dati per la verifica universale) ---
    def publish_board(self) -> dict:
        if not self._closed:
            raise RuntimeError("La bacheca si pubblica a urne chiuse.")
        return {
            "records": list(self.records),
            "root": self.tree.get_root(),
            "signed_root": self.signed_root,
            "collector_cert_pem": PKI.cert_to_pem(self.cert),
        }
