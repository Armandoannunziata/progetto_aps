# crypto/shamir.py
"""Shamir Secret Sharing (schema a soglia, §2.2.4 / D2=A).

Il segreto e' un intero < PRIME. La condivisione avviene su GF(PRIME) con un
primo di Mersenne sufficientemente grande; la ricostruzione usa l'interpolazione
di Lagrange valutata in 0.

Nota d'uso (cfr. actors/counter.py): la chiave privata RSA non viene frammentata
direttamente (sarebbe troppo grande e non ricostruibile come oggetto chiave dal
solo esponente). Si frammenta invece la chiave simmetrica che la incapsula; e'
questa chiave (lunga ~352 bit) a stare comodamente sotto PRIME.
"""
import secrets
import logging

logger = logging.getLogger(__name__)

# Primo di Mersenne 2^521 - 1: campo ampio per ospitare chiavi simmetriche fino a 521 bit.
PRIME = 2 ** 521 - 1


class ShamirSecretSharing:
    @staticmethod
    def _eval_poly(poly, x, prime):
        """Valuta P(x) mod prime con il metodo di Horner."""
        result = 0
        for coeff in reversed(poly):
            result = (result * x + coeff) % prime
        return result

    @staticmethod
    def split_secret(secret_int: int, threshold: int, shares_count: int) -> list:
        """Divide il segreto in 'shares_count' quote; ne servono 'threshold' per ricostruire."""
        if threshold > shares_count:
            raise ValueError("La soglia t non puo' superare il numero di quote n.")
        if threshold < 1:
            raise ValueError("La soglia deve essere >= 1.")
        if secret_int < 0 or secret_int >= PRIME:
            raise ValueError("Il segreto deve essere un intero in [0, PRIME).")

        logger.info(f"Shamir: split del segreto con t={threshold}, n={shares_count}.")
        # P(x) = secret + a_1 x + ... + a_{t-1} x^{t-1}; secret = P(0).
        poly = [secret_int] + [secrets.randbelow(PRIME) for _ in range(threshold - 1)]
        return [(x, ShamirSecretSharing._eval_poly(poly, x, PRIME)) for x in range(1, shares_count + 1)]

    @staticmethod
    def reconstruct_secret(shares: list, prime: int = PRIME) -> int:
        """Ricostruisce P(0) date almeno 'threshold' quote, via Lagrange."""
        if len(shares) < 1:
            raise ValueError("Nessuna quota fornita.")
        logger.info(f"Shamir: ricostruzione del segreto da {len(shares)} quote.")
        secret = 0
        for i, (x_i, y_i) in enumerate(shares):
            num, den = 1, 1
            for j, (x_j, _) in enumerate(shares):
                if i != j:
                    num = (num * (-x_j)) % prime
                    den = (den * (x_i - x_j)) % prime
            lagrange = (num * pow(den, -1, prime)) % prime
            secret = (secret + y_i * lagrange) % prime
        return secret
