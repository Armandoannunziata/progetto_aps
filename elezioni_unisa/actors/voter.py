# actors/voter.py
"""Voter — Elettore (§2.2.1, §2.2.5, §2.3).

Possiede due chiavi distinte:
  - una chiave personale a lungo termine, certificata da UnisaCA, usata SOLO per
    l'autenticazione challenge-response verso AuthUnisa (prova d'identita', A.2);
  - una chiave effimera, generata per la sessione, la cui pubblica finisce nel
    token anonimo e la cui privata firma il ciphertext (legame token<->scheda, D1=A).

Prima di cifrare, l'elettore verifica il certificato di VoteCounter fino a
UnisaCA in hard-fail (§2.2.5): cifrare con una PK_TA non autentica vanificherebbe
S.3/S.5. Dopo la chiusura, verifica la propria ricevuta (Merkle proof) contro la
radice firmata (VI.1).
"""
import logging
from crypto.pki import PKI
from crypto.merkle import MerkleTree
from utils.payload import VotePayload, EncryptedBallot

logger = logging.getLogger(__name__)


class Voter:
    def __init__(self, voter_id, personal_private_key, personal_cert, ca, registrar, collector, counter_cert):
        self.voter_id = voter_id
        self.personal_private_key = personal_private_key
        self.personal_cert = personal_cert
        self.ca = ca
        self.registrar = registrar
        self.collector = collector
        self.counter_cert = counter_cert
        self.seq = None
        self.receipt = None

    def cast_vote(self, election_id: str, choice: str) -> bool:
        logger.info(f"[{self.voter_id}] Avvio procedura di voto...")
        try:
            # 1-2. Challenge-response: il registrar emette un nonce, l'elettore lo firma.
            nonce = self.registrar.issue_challenge(self.voter_id)
            signed_challenge = PKI.sign(self.personal_private_key, nonce)

            # 3. Chiave effimera della sessione.
            eph_priv, eph_pub = PKI.generate_rsa_keypair()
            eph_pub_pem = PKI.pub_to_pem(eph_pub)

            # 4. Richiesta del token anonimo (presenta cert personale + risposta al challenge).
            token = self.registrar.request_voting_token(
                self.voter_id, self.personal_cert, signed_challenge, eph_pub_pem
            )

            # 5. Verifica del certificato di VoteCounter (catena + revoca hard-fail) prima di cifrare.
            self.ca.verify_certificate(self.counter_cert)
            counter_pub = self.counter_cert.public_key()

            # 6. Cifratura del voto (RSA-OAEP) -> C.
            C = PKI.encrypt(counter_pub, VotePayload(election_id, choice).to_bytes())

            # 7. Legame token<->scheda: firma effimera su C (Auth).
            auth = PKI.sign(eph_priv, C)

            # 8. Sottomissione.
            resp = self.collector.submit_ballot(EncryptedBallot(token.token_id, C, auth), token)
            self.seq = resp["seq"]
            logger.info(f"[{self.voter_id}] Voto registrato (seq={self.seq}).")
            return True
        except Exception as e:
            logger.error(f"[{self.voter_id}] Voto NON riuscito: {e}")
            return False

    def fetch_receipt(self):
        """Ottiene la ricevuta a urne chiuse (Merkle proof contro la radice definitiva)."""
        if self.seq is None:
            return None
        self.receipt = self.collector.get_receipt(self.seq)
        return self.receipt

    def verify_receipt(self) -> bool:
        """[VI.1] Verifica l'inclusione del proprio voto e l'autenticita' della radice firmata."""
        if self.receipt is None and self.fetch_receipt() is None:
            logger.warning(f"[{self.voter_id}] Nessuna ricevuta disponibile.")
            return False
        r = self.receipt
        # (a) inclusione: la foglia + proof ricostruiscono la radice pubblicata
        included = MerkleTree.verify_proof(r["leaf_data"], r["proof"], r["root"])
        # (b) autenticita': la radice e' firmata da VoteCollector
        root_authentic = PKI.verify(self.collector.cert.public_key(), r["root"].encode(), r["signed_root"])
        ok = included and root_authentic
        logger.info(f"[{self.voter_id}] Verifica ricevuta: {'VALIDA' if ok else 'FALLITA'} "
                    f"(inclusione={included}, radice_autentica={root_authentic}).")
        return ok
