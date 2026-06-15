# actors/registrar.py
"""AuthUnisa — Autorita' di Autenticazione/Registrazione (§2.2.3, §2.3).

Verifica l'identita' reale dello studente con autenticazione challenge-response
a firma digitale (§2.3 / D2): emette un nonce, lo studente lo firma con la
propria chiave privata certificata da UnisaCA, AuthUnisa verifica il certificato
(catena + revoca hard-fail) e la firma sul nonce. Questo realizza A.2
(non impersonabilita': forgiare la risposta richiederebbe la chiave privata
altrui, infeasible per l'infalsificabilita' esistenziale di RSA) e il non
ripudio della richiesta.

Conclusa l'autenticazione, rilascia un token ANONIMO: token_id casuale, la
chiave pubblica effimera dello studente, e la firma di AuthUnisa su
(token_id || PK_effimera). Il token non contiene l'identita' (S.2).
"""
import logging
import secrets
from cryptography.x509.oid import NameOID

from crypto.pki import PKI
from utils.payload import AuthToken
from actors.ca import UnisaCA

logger = logging.getLogger(__name__)


class AuthUnisa:
    def __init__(self, ca: UnisaCA, eligible_voters, identity: str = "AuthUnisa"):
        self.identity = identity
        logger.info(f"Inizializzazione {self.identity}...")
        self.ca = ca
        self.private_key, self.public_key = PKI.generate_rsa_keypair()
        self.cert = ca.issue_certificate(self.identity, self.public_key)

        # Elenco aventi diritto: matricola -> ha gia' ottenuto un token? (U.1)
        self.eligible_voters = {m: False for m in eligible_voters}

        self._pending_challenges = {}  # matricola -> nonce in attesa (freschezza)

    # --- fase 1: challenge ---
    def issue_challenge(self, voter_id: str) -> bytes:
        """Emette un nonce fresco per l'autenticazione challenge-response."""
        nonce = secrets.token_bytes(32)
        self._pending_challenges[voter_id] = nonce
        return nonce

    # --- fase 2: rilascio token ---
    def request_voting_token(self, voter_id: str, voter_cert,
                             signed_challenge: bytes, voter_ephemeral_pub_pem: bytes) -> AuthToken:
        # (a) Verifica il certificato personale dello studente: catena fino a UnisaCA + revoca hard-fail.
        try:
            self.ca.verify_certificate(voter_cert)
        except (PermissionError, ValueError) as e:
            logger.error(f"[{self.identity}] Certificato dello studente non valido: {e}")
            raise PermissionError(f"Autenticazione fallita: {e}")

        # (b) Lega l'identita' dichiarata al certificato: il CN deve coincidere con la matricola.
        cert_cn = voter_cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value
        if cert_cn != voter_id:
            raise PermissionError("Identita' dichiarata diversa dal soggetto del certificato.")

        # (c) Verifica challenge-response: firma del nonce con la chiave del certificato (A.2).
        nonce = self._pending_challenges.get(voter_id)
        if nonce is None:
            raise PermissionError("Nessun challenge in attesa: richiedere prima un nonce.")
        if not PKI.verify(voter_cert.public_key(), nonce, signed_challenge):
            raise PermissionError("Risposta al challenge non valida (firma sul nonce errata).")
        del self._pending_challenges[voter_id]  # nonce monouso

        # (d) Diritto di voto (A.1) e unicita' del rilascio (U.1).
        if voter_id not in self.eligible_voters:
            raise PermissionError("Studente non presente nell'elenco degli aventi diritto.")
        if self.eligible_voters[voter_id]:
            raise ValueError("Token gia' rilasciato a questa matricola (U.1).")

        # (e) Rilascio del token anonimo: token_id casuale [D7], firma su (token_id || PK_eff).
        token_id = "TK-" + secrets.token_hex(16)
        token = AuthToken(
            token_id=token_id,
            voter_ephemeral_pub_key_pem=voter_ephemeral_pub_pem,
            registrar_signature=b"",
        )
        token.registrar_signature = PKI.sign(self.private_key, token.signed_payload())

        self.eligible_voters[voter_id] = True
        logger.info(f"[{self.identity}] Token {token_id} rilasciato (anonimo) a un avente diritto.")
        return token

    # numero di token leciti emessi: serve alla riconciliazione a posteriori (VU.2 / A.1)
    def issued_token_count(self) -> int:
        return sum(1 for v in self.eligible_voters.values() if v)
