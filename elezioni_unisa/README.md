# VoteUnisa — WP4: Implementazione e prestazioni

Implementazione in ambiente simulato (applicazione stand-alone, processo unico)
del protocollo di voto elettronico progettato nel WP2. Tutte le primitive
appartengono al programma del corso; nessuna libreria o tecnica esterna.

## Requisiti

```
pip install -r requirements.txt        # solo: cryptography
```

## Esecuzione

```
cd elezioni_unisa
python3 main.py            # flusso onesto + attacchi + scrutinio + verifica universale
python3 benchmark.py       # micro-benchmark, dimensioni messaggi, sweep di scala N
python3 test_crypto.py     # test unitari delle primitive e dei componenti
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
