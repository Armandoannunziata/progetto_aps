# VoteUnisa — WP4: Implementazione e prestazioni

Implementazione in ambiente simulato (applicazione stand-alone, processo unico)
del protocollo di voto elettronico progettato nel WP2. Tutte le primitive
appartengono al programma del corso; nessuna libreria o tecnica esterna.

## Requisiti

Python 3.10+ (testato su 3.13). Unica dipendenza esterna: `cryptography`; il resto è
standard library (`tkinter` incluso, usato dalla GUI). Si consiglia un ambiente
virtuale dedicato; i comandi sono cross-platform (Windows, macOS, Linux):

```
python -m venv .venv
# attivazione:
#   Windows (PowerShell/cmd):  .venv\Scripts\activate
#   macOS / Linux:             source .venv/bin/activate
pip install -r requirements.txt        # solo: cryptography
```

Nota Linux: se `import tkinter` fallisce, installare il pacchetto di sistema
`python3-tk` (es. Debian/Ubuntu: `sudo apt install python3-tk`).

## Esecuzione

I moduli (`crypto`, `actors`, `utils`) sono risolti dalla cartella di lavoro: lanciare
sempre **dalla directory `elezioni_unisa/`**, con il `python` dell'ambiente in cui sono
installate le dipendenze (su Windows in alternativa `py`).

```
cd elezioni_unisa
python main.py            # flusso onesto + attacchi + scrutinio + verifica universale
python gui.py             # GUI: esecuzione on-demand dei singoli scenari/attacchi
python benchmark.py       # micro-benchmark, dimensioni messaggi, sweep di scala N
python test_crypto.py     # test unitari delle primitive e dei componenti
```

## Mappa moduli -> WP2/WP3

| File | Ruolo | Riferimento |
|------|-------|-------------|
| `crypto/pki.py` | RSA-OAEP, RSA-PSS, X.509 (catena, CRL) | §2.1, §2.2.5, §2.2.7 |
| `crypto/shamir.py` | Secret sharing a soglia | §2.2.4 |
| `crypto/merkle.py` | Urna Merkle (build batch, congelamento) | §2.2.6, §2.2.8 |
| `actors/ca.py` | UnisaCA: emissione certificati, CRL, hard-fail | §2.2.5, §2.2.7 |
| `actors/registrar.py` | AuthUnisa: challenge-response, token anonimo | §2.2.3, §2.3 |
| `actors/collector.py` | VoteCollector: verifica, urna, firma radice | §2.2.1, §2.2.2, §2.2.6, §2.2.8 |
| `actors/counter.py` | VoteCounter: secret sharing, scrutinio, chiari (C,v) | §2.2.4, §2.2.8 |
| `actors/voter.py` | Elettore: voto + verifica ricevuta | §2.2.1, §2.2.5, §2.3 |
| `bulletin_board.py` | Bacheca pubblica (dati pubblicati) | §2.2.6, §2.2.8 |
| `verifier.py` | Verifica universale eseguibile da chiunque | §2.2.8 (VU.1, VU.2, VU.3, I.5–I.7) |
| `scenarios.py` | Scenari riusabili (flusso onesto, attacchi, scrutinio, verifica) | WP3 threat model |
| `gui.py` | GUI (tkinter) per l'esecuzione on-demand degli scenari | — |

## Proprietà dimostrate in `main.py`

- A.2 (challenge-response), A.3 (firma del token), U.1/U.2 (token unico/speso),
  I.1 (manomissione urna rilevata), I.4 (alterazione in transito rilevata),
  S.3 (apertura sotto-soglia impossibile), VI.1 (ricevuta contro radice firmata),
  VU.1/VU.2/VU.3 (verifica universale), I.6/I.7 (scarti e quorum ricontabili).
- §2.2.7: hard-fail su CRL non disponibile (The Eavesdropper v.2).

## Limite residuo (coerente con §1.5 e §2.2.8)

Il verificatore universale accerta la corrispondenza urna<->ciphertext e la
correttezza aritmetica del conteggio, ma non puo' verificare che il chiaro `v`
sia la decifrazione onesta del ciphertext `C` (manca la decifrazione verificabile,
fuori dal corso). Questo limite cede solo sotto collusione dell'intera soglia di
VoteCounter, gia' dichiarata come rischio residuo.
