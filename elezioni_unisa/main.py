# main.py
"""Simulazione end-to-end del referendum (WP4).

Punto d'ingresso del flusso completo: esegue il flusso onesto, la batteria di
attacchi del threat model di WP3 attraverso i PERCORSI REALI del codice, la
chiusura con firma della radice, lo scrutinio verificabile e la verifica
universale con calcolo del quorum.

La logica dei singoli scenari vive in scenarios.py (riusata anche dalla GUI di
esecuzione on-demand, gui.py); qui si lancia soltanto la sequenza completa.
"""
import logging

from utils.logger import setup_logging
import scenarios

setup_logging(logging.INFO)


def run():
    scenarios.full_flow()


if __name__ == "__main__":
    run()
