# test_crypto.py
"""Test unitari delle primitive e dei componenti chiave (eseguibile con: python3 test_crypto.py)."""
import logging
logging.disable(logging.INFO)

from crypto.pki import PKI
from crypto.shamir import ShamirSecretSharing
from crypto.merkle import MerkleTree
from actors.ca import UnisaCA


def test_signatures_and_encryption():
    priv, pub = PKI.generate_rsa_keypair(2048)
    m = b"voto di prova"
    assert PKI.verify(pub, m, PKI.sign(priv, m))
    assert not PKI.verify(pub, b"altro", PKI.sign(priv, m))
    ct = PKI.encrypt(pub, m)
    assert PKI.decrypt(priv, ct) == m
    # OAEP probabilistico: due cifrature dello stesso messaggio differiscono (S.7)
    assert PKI.encrypt(pub, m) != PKI.encrypt(pub, m)
    print("PKI firme/cifratura: OK")


def test_x509_chain_and_crl():
    ca_priv, ca_pub = PKI.generate_rsa_keypair(2048)
    root = PKI.create_self_signed_ca("UnisaCA", ca_priv)
    leaf_priv, leaf_pub = PKI.generate_rsa_keypair(2048)
    leaf = PKI.issue_certificate("VoteCounter", leaf_pub, ca_priv, root)
    assert PKI.verify_chain(leaf, root)
    crl = PKI.build_crl(ca_priv, root, [])
    assert not PKI.is_revoked(leaf, crl)
    crl2 = PKI.build_crl(ca_priv, root, [leaf.serial_number])
    assert PKI.is_revoked(leaf, crl2)
    # un certificato auto-firmato non risale alla CA
    self_priv, _ = PKI.generate_rsa_keypair(2048)
    self_cert = PKI.create_self_signed_ca("Impostore", self_priv)
    try:
        PKI.verify_chain(self_cert, root); assert False
    except ValueError:
        pass
    print("X.509 catena/CRL: OK")


def test_shamir():
    s = 0xDEADBEEFCAFE
    shares = ShamirSecretSharing.split_secret(s, 3, 5)
    assert ShamirSecretSharing.reconstruct_secret([shares[0], shares[2], shares[4]]) == s
    assert ShamirSecretSharing.reconstruct_secret([shares[1], shares[3], shares[4]]) == s
    print("Shamir 3/5: OK")


def test_merkle_freeze_and_proof():
    t = MerkleTree()
    idxs = [t.add_leaf(f"v{i}".encode()) for i in range(5)]
    t.build()
    root = t.get_root()
    # tutte le foglie verificano contro la radice DEFINITIVA (baco staleness risolto)
    for i in idxs:
        assert MerkleTree.verify_proof(f"v{i}".encode(), t.get_proof(i), root)
    # una foglia errata non verifica
    assert not MerkleTree.verify_proof(b"vX", t.get_proof(0), root)
    print("Merkle build/proof (radice finale): OK")


def test_ca_revocation():
    """Esercita il ciclo di revoca dell'attore UnisaCA (emissione -> revoca ->
    ricostruzione CRL -> rifiuto). Verifica la coerenza con WP3: un certificato
    valido viene accettato finche' la CRL disponibile non lo elenca, e dopo la
    revoca il controllo hard-fail (verify_certificate) lo rigetta."""
    ca = UnisaCA()
    priv, pub = PKI.generate_rsa_keypair(2048)
    cert = ca.issue_certificate("ElettoreRevocando", pub)
    # prima della revoca: catena valida, CRL disponibile e non lo elenca -> accettato
    assert ca.verify_certificate(cert) is True
    assert not PKI.is_revoked(cert, ca.get_crl())
    # revoca: il serial entra nella CRL, che viene ricostruita e ri-firmata dalla CA
    ca.revoke(cert)
    assert PKI.is_revoked(cert, ca.get_crl())
    # dopo la revoca: verify_certificate rigetta con PermissionError (revocato)
    try:
        ca.verify_certificate(cert); assert False
    except PermissionError:
        pass
    print("UnisaCA emissione/revoca/CRL: OK")


if __name__ == "__main__":
    test_signatures_and_encryption()
    test_x509_chain_and_crl()
    test_shamir()
    test_merkle_freeze_and_proof()
    test_ca_revocation()
    print("\nTutti i test superati.")
