# crypto/merkle.py
"""Merkle tree dell'urna pubblica (§2.2.6).

Differenza rispetto alla versione iniziale:
  - costruzione BATCH una sola volta (build), non ricostruzione a ogni inserimento:
    elimina il costo O(n^2) rilevante per il benchmark (D6=a);
  - le foglie si accumulano append-only; le Merkle proof si emettono SOLO dopo
    il congelamento (build), cioe' contro la radice DEFINITIVA. Questo corregge
    il baco per cui una ricevuta catturata alla sottomissione non verificava piu'
    contro la radice finale, ed e' coerente con §2.2.8: 'VoteCollector congela
    l'urna e firma la radice'.

Convenzione (la stessa delle esercitazioni del corso):
  - foglia memorizzata = SHA-256(leaf_data) in esadecimale;
  - nodo padre = SHA-256( hex(figlio_sx) || hex(figlio_dx) );
  - numero dispari di nodi a un livello -> l'ultimo si duplica.
"""
import hashlib
import logging

logger = logging.getLogger(__name__)


def sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


class MerkleTree:
    def __init__(self):
        self.leaves = []      # hash esadecimali delle foglie
        self.levels = []      # livelli, dal basso (foglie) all'alto (radice)
        self._built = False

    # --- costruzione ---
    def add_leaf(self, leaf_data: bytes) -> int:
        """Accumula una foglia (non costruisce). Ritorna l'indice della foglia."""
        if self._built:
            raise RuntimeError("Albero gia' congelato: nessuna foglia puo' essere aggiunta.")
        self.leaves.append(sha256_hex(leaf_data))
        return len(self.leaves) - 1

    def build(self):
        """Costruisce i livelli una sola volta e congela l'albero."""
        if not self.leaves:
            self.levels = []
            self._built = True
            return
        current = list(self.leaves)
        self.levels = [current]
        while len(current) > 1:
            nxt = []
            for i in range(0, len(current), 2):
                left = current[i]
                right = current[i + 1] if i + 1 < len(current) else left  # duplica se dispari
                nxt.append(sha256_hex((left + right).encode()))
            self.levels.append(nxt)
            current = nxt
        self._built = True
        logger.debug(f"Merkle tree costruito: {len(self.leaves)} foglie, {len(self.levels)} livelli.")

    @classmethod
    def from_leaves(cls, leaf_data_list) -> "MerkleTree":
        """Costruisce direttamente da una lista ordinata di dati-foglia (usato dal verificatore)."""
        t = cls()
        for d in leaf_data_list:
            t.add_leaf(d)
        t.build()
        return t

    # --- interrogazione ---
    def get_root(self) -> str:
        if not self._built:
            raise RuntimeError("Albero non ancora costruito: chiamare build().")
        if not self.levels:
            return ""
        return self.levels[-1][0]

    def get_proof(self, leaf_index: int) -> list:
        """Merkle proof per la foglia indicata, contro la radice DEFINITIVA."""
        if not self._built:
            raise RuntimeError("Albero non ancora costruito: chiamare build().")
        if leaf_index < 0 or leaf_index >= len(self.leaves):
            raise IndexError("Indice foglia non valido.")
        proof = []
        idx = leaf_index
        for level in self.levels[:-1]:
            if idx % 2 == 0:
                sib = idx + 1 if idx + 1 < len(level) else idx  # se ultimo dispari, fratello = se' stesso
                position = "right"
            else:
                sib = idx - 1
                position = "left"
            proof.append({"sibling_hash": level[sib], "position": position})
            idx //= 2
        return proof

    @staticmethod
    def verify_proof(leaf_data: bytes, proof: list, root: str) -> bool:
        """Verifica deterministica (VI.1 / VU.3): ricostruisce la radice dalla foglia + proof."""
        current = sha256_hex(leaf_data)
        for step in proof:
            sib = step["sibling_hash"]
            if step["position"] == "left":
                current = sha256_hex((sib + current).encode())
            else:
                current = sha256_hex((current + sib).encode())
        return current == root
