# crypto/pki.py
"""Primitive crittografiche e supporto PKI X.509 (§2.1, §2.2.5, §2.2.7).

Due livelli, deliberatamente distinti:
  - Firme/cifrature a livello APPLICATIVO (token, schede, radice dell'urna,
    risposta al challenge): RSA-PSS e RSA-OAEP con SHA-256, come da §2.1.
  - Firme dei CERTIFICATI X.509: padding PKCS#1 v1.5, che e' la convenzione
    standard dell'X.509 (la libreria firma i certificati cosi'). Questo non
    contraddice la preferenza del corso per PSS, che riguarda le firme
    applicative; la distinzione e' esplicitata qui per chiarezza.

La verifica dei certificati implementa la catena fino a UnisaCA e il controllo
di revoca; la modalita' hard-fail (§2.2.7) e' realizzata in actors/ca.py, che
nega l'operazione quando lo stato di revoca non e' disponibile.
"""
import datetime
import logging

from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.exceptions import InvalidSignature

logger = logging.getLogger(__name__)

_OAEP = padding.OAEP(mgf=padding.MGF1(hashes.SHA256()), algorithm=hashes.SHA256(), label=None)
_PSS = padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH)


class PKI:
    # ---------- primitive ----------
    @staticmethod
    def generate_rsa_keypair(key_size: int = 2048):
        priv = rsa.generate_private_key(public_exponent=65537, key_size=key_size)
        return priv, priv.public_key()

    @staticmethod
    def sign(private_key, message: bytes) -> bytes:
        """Firma applicativa RSA-PSS con SHA-256 (probabilistica)."""
        return private_key.sign(message, _PSS, hashes.SHA256())

    @staticmethod
    def verify(public_key, message: bytes, signature: bytes) -> bool:
        try:
            public_key.verify(signature, message, _PSS, hashes.SHA256())
            return True
        except InvalidSignature:
            return False

    @staticmethod
    def encrypt(public_key, plaintext: bytes) -> bytes:
        """Cifratura RSA-OAEP con SHA-256 (probabilistica -> realizza S.7)."""
        return public_key.encrypt(plaintext, _OAEP)

    @staticmethod
    def decrypt(private_key, ciphertext: bytes) -> bytes:
        return private_key.decrypt(ciphertext, _OAEP)

    # ---------- X.509 ----------
    @staticmethod
    def create_self_signed_ca(common_name: str, private_key, days: int = 3650) -> x509.Certificate:
        now = datetime.datetime.now(datetime.timezone.utc)
        name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, common_name)])
        return (
            x509.CertificateBuilder()
            .subject_name(name).issuer_name(name)
            .public_key(private_key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(now).not_valid_after(now + datetime.timedelta(days=days))
            .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
            .sign(private_key, hashes.SHA256())
        )

    @staticmethod
    def issue_certificate(subject_cn: str, subject_public_key,
                          issuer_private_key, issuer_cert: x509.Certificate,
                          days: int = 365) -> x509.Certificate:
        now = datetime.datetime.now(datetime.timezone.utc)
        return (
            x509.CertificateBuilder()
            .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, subject_cn)]))
            .issuer_name(issuer_cert.subject)
            .public_key(subject_public_key)
            .serial_number(x509.random_serial_number())
            .not_valid_before(now).not_valid_after(now + datetime.timedelta(days=days))
            .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
            .sign(issuer_private_key, hashes.SHA256())
        )

    @staticmethod
    def build_crl(issuer_private_key, issuer_cert: x509.Certificate, revoked_serials) -> x509.CertificateRevocationList:
        now = datetime.datetime.now(datetime.timezone.utc)
        builder = (
            x509.CertificateRevocationListBuilder()
            .issuer_name(issuer_cert.subject)
            .last_update(now).next_update(now + datetime.timedelta(days=1))
        )
        for serial in revoked_serials:
            revoked = x509.RevokedCertificateBuilder().serial_number(serial).revocation_date(now).build()
            builder = builder.add_revoked_certificate(revoked)
        return builder.sign(issuer_private_key, hashes.SHA256())

    @staticmethod
    def verify_chain(cert: x509.Certificate, root_cert: x509.Certificate) -> bool:
        """Verifica che 'cert' sia firmato da 'root_cert' e dentro la finestra di validita'.
        Solleva ValueError in caso di fallimento (cosi' i chiamanti possono distinguere i motivi)."""
        if cert.issuer != root_cert.subject:
            raise ValueError("Issuer del certificato diverso dalla CA radice.")
        now = datetime.datetime.now(datetime.timezone.utc)
        if not (cert.not_valid_before_utc <= now <= cert.not_valid_after_utc):
            raise ValueError("Certificato fuori dalla finestra di validita'.")
        try:
            # Padding PKCS#1 v1.5 (NON PSS): qui si verifica la firma con cui la CA ha
            # firmato il CERTIFICATO X.509, e quel padding e' fissato dal formato del
            # certificato stesso (campo signatureAlgorithm), non scelto da noi. La
            # libreria 'cryptography' emette i certificati con RSA + PKCS#1 v1.5, quindi
            # la verifica deve usare lo stesso schema, altrimenti la firma non torna.
            # Questo NON e' in contrasto con la preferenza del corso per PSS: PSS regola
            # le firme APPLICATIVE (token, schede, radice dell'urna, risposta al
            # challenge) in PKI.sign/PKI.verify; la firma del certificato e' un livello
            # diverso, governato dallo standard X.509. La sicurezza non ne risente: in
            # entrambi i casi l'inforgiabilita' poggia su RSA a 2048 bit + SHA-256.
            root_cert.public_key().verify(
                cert.signature, cert.tbs_certificate_bytes,
                padding.PKCS1v15(), cert.signature_hash_algorithm,
            )
        except InvalidSignature:
            raise ValueError("Firma della CA sul certificato non valida.")
        return True

    @staticmethod
    def is_revoked(cert: x509.Certificate, crl: x509.CertificateRevocationList) -> bool:
        return crl.get_revoked_certificate_by_serial_number(cert.serial_number) is not None

    # ---------- serializzazione (dati pubblici) ----------
    @staticmethod
    def cert_to_pem(cert: x509.Certificate) -> bytes:
        return cert.public_bytes(serialization.Encoding.PEM)

    @staticmethod
    def cert_from_pem(pem: bytes) -> x509.Certificate:
        return x509.load_pem_x509_certificate(pem)

    @staticmethod
    def pub_to_pem(public_key) -> bytes:
        return public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )

    @staticmethod
    def pub_from_pem(pem: bytes):
        return serialization.load_pem_public_key(pem)
