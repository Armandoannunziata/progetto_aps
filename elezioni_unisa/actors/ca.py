# actors/ca.py
"""UnisaCA — Certification Authority di ateneo (§2.2.5, §2.2.7).

Radice di fiducia: una CA auto-firmata. Emette certificati X.509 per gli attori
e per gli studenti, mantiene una CRL firmata e verifica i certificati in modalita'
HARD-FAIL: se lo stato di revoca non e' disponibile, la verifica FALLISCE (il
certificato viene rifiutato anziche' accettato). Il flag crl_available modella
l'attaccante attivo di §2.2.7 (The Eavesdropper v.2) che blocca le richieste di
revoca per indurre il rifiuto di voti legittimi (disenfranchisement).
"""
import logging
from crypto.pki import PKI

logger = logging.getLogger(__name__)


class UnisaCA:
    def __init__(self, common_name: str = "UnisaCA"):
        logger.info(f"Inizializzazione {common_name} (CA radice)...")
        self.private_key, self.public_key = PKI.generate_rsa_keypair(4096)
        self.cert = PKI.create_self_signed_ca(common_name, self.private_key)

        self._revoked_serials = set()             # numeri di serie revocati
        self.crl = PKI.build_crl(self.private_key, self.cert, self._revoked_serials)
        self.crl_available = True                 # se False, hard-fail rigetta (Eavesdropper v.2)

    # --- distribuzione fiducia ---
    def get_root_cert(self):
        return self.cert

    def issue_certificate(self, subject_cn: str, subject_public_key, days: int = 365):
        cert = PKI.issue_certificate(subject_cn, subject_public_key, self.private_key, self.cert, days)
        logger.info(f"[CA] Certificato emesso per '{subject_cn}' (serial {cert.serial_number}).")
        return cert

    # --- revoca ---
    def revoke(self, cert):
        self._revoked_serials.add(cert.serial_number)
        self.crl = PKI.build_crl(self.private_key, self.cert, self._revoked_serials)
        logger.warning(f"[CA] Certificato '{_cn(cert)}' REVOCATO (serial {cert.serial_number}).")

    def get_crl(self):
        """Restituisce la CRL firmata, o None se il servizio non e' disponibile (hard-fail)."""
        return self.crl if self.crl_available else None

    # --- verifica (hard-fail) ---
    def verify_certificate(self, cert) -> bool:
        """Verifica catena + validita' + stato di revoca in HARD-FAIL.
        Solleva PermissionError/ValueError in caso di rifiuto."""
        PKI.verify_chain(cert, self.cert)           # catena fino alla radice + finestra di validita'
        crl = self.get_crl()
        if crl is None:
            # Hard-fail: assenza di conferma di non-revoca => rifiuto.
            raise PermissionError("Stato di revoca non disponibile: certificato rifiutato (hard-fail).")
        if PKI.is_revoked(cert, crl):
            raise PermissionError(f"Certificato '{_cn(cert)}' revocato.")
        return True


def _cn(cert) -> str:
    try:
        from cryptography.x509.oid import NameOID
        return cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value
    except Exception:
        return "?"
