# utils/payload.py
"""Strutture dati del protocollo.

Le scelte di formato qui riflettono fedelmente WP2:
  - VotePayload  -> §2.2.1 / D10: dominio chiuso {SI, NO, BIANCA} legato all'ElectionID.
  - AuthToken    -> §2.2.3 / D1=A: token anonimo con chiave pubblica effimera, firmato da AuthUnisa.
  - EncryptedBallot -> §2.2.1: (C, token, Auth) con Auth = firma effimera sul ciphertext.
  - PublicRecord -> §2.2.8 / VU.2: l'unità pubblicata nella bacheca, ricontrollabile da chiunque.
"""
from dataclasses import dataclass, field
import json
import hashlib


# Costanti di dominio del voto (D10). Sono tre stringhe predefinite e distinte.
CHOICES = ("SI", "NO", "BIANCA")


@dataclass
class VotePayload:
    """Voto in chiaro. [D10] dominio chiuso + ElectionID contro il replay cross-election."""
    election_id: str
    choice: str  # atteso in CHOICES

    def to_bytes(self) -> bytes:
        # Serializzazione deterministica: ordine delle chiavi fissato.
        return json.dumps(
            {"election_id": self.election_id, "choice": self.choice},
            sort_keys=True,
            separators=(",", ":"),
        ).encode()


@dataclass
class AuthToken:
    """[D1=A] Token anonimo. Non contiene l'identità: contiene la chiave pubblica
    effimera generata dall'elettore per la sessione, e la firma di AuthUnisa su
    (token_id || chiave_effimera)."""
    token_id: str
    voter_ephemeral_pub_key_pem: bytes
    registrar_signature: bytes

    def signed_payload(self) -> bytes:
        """I byte effettivamente firmati da AuthUnisa: token_id || PK_effimera."""
        return self.token_id.encode() + self.voter_ephemeral_pub_key_pem


@dataclass
class EncryptedBallot:
    """[§2.2.1] Scheda (C, token, Auth). 'Auth' = ephemeral_signature, firma del
    ciphertext con la chiave PRIVATA effimera corrispondente a quella nel token."""
    token_id: str
    ciphertext: bytes          # C = RSA-OAEP(PK_VoteCounter, VotePayload)
    ephemeral_signature: bytes  # Auth = Sign(SK_eff, C)

    def get_leaf_data(self) -> bytes:
        """[D3=A / D8] Dato-foglia del Merkle tree: H(C) || H(token_id).
        La foglia memorizzata nell'albero è poi SHA-256 di questo valore
        (cfr. crypto/merkle.py), ossia leaf = H( H(C) || H(token_id) )."""
        h_c = hashlib.sha256(self.ciphertext).digest()
        h_t = hashlib.sha256(self.token_id.encode()).digest()
        return h_c + h_t


@dataclass
class PublicRecord:
    """[§2.2.8 / VU.2] Unità pubblicata nella bacheca per la verifica universale.
    Contiene tutto ciò che serve a un osservatore esterno per:
      - ricostruire la foglia e quindi la radice (VU.1),
      - verificare che la scheda rechi un token valido firmato da AuthUnisa (VU.2),
      - verificare il legame token<->ciphertext (D1=A),
      - rilevare token duplicati (VU.2)."""
    seq: int
    ciphertext: bytes
    token_id: str
    ephemeral_pub_key_pem: bytes
    registrar_signature: bytes
    ephemeral_signature: bytes

    def to_ballot(self) -> "EncryptedBallot":
        return EncryptedBallot(self.token_id, self.ciphertext, self.ephemeral_signature)

    def to_token(self) -> "AuthToken":
        return AuthToken(self.token_id, self.ephemeral_pub_key_pem, self.registrar_signature)

    def leaf_data(self) -> bytes:
        return self.to_ballot().get_leaf_data()
