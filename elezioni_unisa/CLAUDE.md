# elezioni_unisa/ — Codice del WP4 (implementazione completa e funzionante)

Questa cartella contiene l'implementazione COMPLETA del WP4, già realizzata e
funzionante: `main.py`, `benchmark.py` e `test_crypto.py` girano e passano allo
stato attuale. Le regole qui sotto servono a MANTENERE la coerenza quando si
modifica il codice, non a costruirlo da zero. Vale la Regola d'Oro della cartella
madre: solo primitive del corso, solo libreria `cryptography` (hazmat).

## Struttura attuale
```
elezioni_unisa/
├── main.py            # orchestrazione: setup PKI, voto onesto, attacchi, chiusura, scrutinio, verifica universale
├── benchmark.py       # micro-benchmark, dimensioni messaggi, sweep di scala N
├── test_crypto.py     # test unitari (primitive, X.509, Shamir, Merkle)
├── verifier.py        # verifica universale standalone (dai soli dati pubblici)
├── bulletin_board.py  # bacheca pubblica: oggetto dei dati pubblicati
├── requirements.txt   # solo: cryptography
├── README.md
├── crypto/
│   ├── pki.py         # RSA-OAEP/PSS + X.509 (catena, CRL, hard-fail)
│   ├── shamir.py      # Shamir Secret Sharing t-su-n
│   └── merkle.py      # Merkle tree (costruzione batch + congelamento)
├── actors/
│   ├── ca.py          # UnisaCA (CA radice, emissione cert, CRL)
│   ├── registrar.py   # AuthUnisa (challenge-response, token anonimo)
│   ├── collector.py   # VoteCollector (urna, radice firmata)
│   ├── counter.py     # VoteCounter (secret sharing, scrutinio)
│   └── voter.py       # Voter (voto + verifica ricevuta)
└── utils/
    ├── logger.py      # configurazione logging
    └── payload.py     # strutture dati (voto, token, scheda, record pubblico)
```

## Vincolo di fedeltà
Il codice riflette le scelte del nostro WP2 (in `../Project_work/`). Mantienilo
fedele: nessuna scorciatoia, nessuna libreria fuori perimetro, nessun meccanismo non
teorizzato in WP2. Se trovi che codice e documento divergono, è un disallineamento
da segnalare, non da "sanare" modificando il documento in autonomia.

## Cosa è già implementato (da preservare)
- Voto: dominio chiuso {SI, NO, BIANCA} con ElectionID nel payload.
- Scheda: C = RSA-OAEP(PK_VoteCounter, voto); firma effimera su C (legame
  token↔scheda); token anonimo firmato RSA-PSS da AuthUnisa; registro dei token spesi.
- Autenticazione: challenge-response a firma (chiave personale dello studente
  certificata da UnisaCA); token_id casuale (CSPRNG).
- Urna: Merkle tree (SHA-256), costruzione batch e congelamento; radice FIRMATA da
  VoteCollector alla chiusura; ricevuta = Merkle proof contro la radice definitiva.
- Scrutinio: Shamir 3/5 sulla chiave di scrutinio (via wrapping Fernet), ricostruita
  solo a urne chiuse; pubblicazione delle coppie (C,v); riconteggio pubblico.
- PKI: X.509 reale (UnisaCA radice, certificati attori/studenti) + CRL in hard-fail.
- Verifica universale: `verifier.py`, eseguibile da chiunque dai soli dati pubblici;
  quorum 50%+1 (le bianche contano tra i validi).
- Assenti per scelta: DH manuale AA↔VoteCollector; revoca del voto; decifrazione
  distribuita verificabile o HSM (lavoro futuro dichiarato in §1.5). Non reintrodurli.

## Esecuzione e verifica
Tutti e tre girano allo stato attuale. Dopo OGNI modifica, rieseguili e riporta
l'output reale; non dedurre il funzionamento dalla sola lettura.
```
python3 main.py          # flusso onesto + attacchi + scrutinio + verifica universale
python3 benchmark.py     # micro-benchmark, dimensioni messaggi, sweep di scala
python3 test_crypto.py   # test unitari
```
Le simulazioni d'attacco devono passare per i percorsi reali degli attori (la
sottomissione di una scheda manomessa va attraverso `collector.submit_ballot`, non
messa in scena).

## Note sullo stato attuale
- Il logging è centralizzato in `utils/logger.py` e attualmente scrive su stderr:
  in console (es. PyCharm) l'ordine delle righe rispetto ai `print` può apparire
  incrociato. È un effetto puramente estetico; se si vuole l'ordine coerente, si può
  instradare il logging su stdout (modifica opzionale, non ancora applicata).
