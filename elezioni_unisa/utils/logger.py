# utils/logger.py
"""Configurazione centralizzata del logging per la simulazione.

Tutti i moduli ottengono il logger tramite logging.getLogger(__name__); qui si
imposta una sola volta il formato e il livello, in modo che main.py, benchmark.py
e i test producano un output coerente e leggibile.
"""
import logging


def setup_logging(level: int = logging.INFO, fmt: str = "%(message)s") -> None:
    """Inizializza il logging root. Idempotente: chiamate ripetute non aggiungono handler."""
    root = logging.getLogger()
    if root.handlers:
        root.setLevel(level)
        return
    logging.basicConfig(level=level, format=fmt)
