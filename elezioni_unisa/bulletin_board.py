# bulletin_board.py
"""Bacheca pubblica (§2.2.6, §2.2.8).

Contenitore dei SOLI dati pubblici dell'elezione, cio' che un osservatore esterno
puo' leggere e su cui esegue le verifiche universali. Aggrega quanto prodotto da
VoteCollector (urna congelata + radice firmata + record) e da VoteCounter (chiari
(C, v) + aggregati), con le ancore di fiducia (certificato radice di UnisaCA, CRL,
certificato di AuthUnisa). Non contiene chiavi private ne' identita'.
"""
from dataclasses import dataclass
from typing import List, Tuple
from crypto.pki import PKI


@dataclass
class PublicBulletin:
    election_id: str
    electorate_size: int
    # urna
    records: list                 # list[PublicRecord]
    root: str
    signed_root: bytes
    # scrutinio
    aggregates: dict              # {SI, NO, BIANCA}
    valid_total: int
    discarded_corrupt: int
    discarded_domain: int
    scrutiny: List[Tuple[int, bytes, str]]   # [(seq, C, v)]
    # ancore di fiducia (PEM)
    root_cert_pem: bytes
    crl_pem: bytes
    registrar_cert_pem: bytes
    collector_cert_pem: bytes
    counter_cert_pem: bytes

    @staticmethod
    def assemble(election_id, electorate_size, board, scrutiny_result, ca, registrar_cert) -> "PublicBulletin":
        from cryptography.x509 import load_pem_x509_crl  # noqa: F401 (documenta la dipendenza)
        return PublicBulletin(
            election_id=election_id,
            electorate_size=electorate_size,
            records=board["records"],
            root=board["root"],
            signed_root=board["signed_root"],
            aggregates=scrutiny_result["aggregates"],
            valid_total=scrutiny_result["valid_total"],
            discarded_corrupt=scrutiny_result["discarded_corrupt"],
            discarded_domain=scrutiny_result["discarded_domain"],
            scrutiny=scrutiny_result["scrutiny"],
            root_cert_pem=PKI.cert_to_pem(ca.get_root_cert()),
            crl_pem=ca.get_crl().public_bytes(_pem()),
            registrar_cert_pem=PKI.cert_to_pem(registrar_cert),
            collector_cert_pem=board["collector_cert_pem"],
            counter_cert_pem=scrutiny_result["counter_cert_pem"],
        )


def _pem():
    from cryptography.hazmat.primitives.serialization import Encoding
    return Encoding.PEM
