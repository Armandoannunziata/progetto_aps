# scenarios.py
"""Scenari eseguibili della simulazione (WP4), isolati e richiamabili on-demand.

Raccoglie in funzioni indipendenti la logica che prima viveva inline in main.py:
il flusso onesto, i singoli attacchi del threat model di WP3, la chiusura con
scrutinio verificabile e la verifica universale. Ogni scenario passa per i
PERCORSI REALI degli attori (nessuna messinscena): le schede manomesse attraversano
collector.submit_ballot, i token contraffatti la verifica di firma, ecc.

Modello di stato. Ogni scenario ha firma uniforme `scenario(env=None, voters=None)`:
  - chiamato SENZA argomenti (caso GUI), costruisce un ambiente fresco e le proprie
    precondizioni minime, quindi e' eseguibile da solo e in qualsiasi ordine;
  - chiamato con un `env` (e dove serve i `voters`) condiviso (caso full_flow),
    riusa quello stato per mantenere la narrativa continua dell'esecuzione completa.
Le funzioni della coda (scrutinio, verifica universale, manomissione urna) ricavano
da sole un'urna chiusa e scrutinata: close() e tally() sono idempotenti e non
mutano il collector, quindi richiamarli su un env gia' chiuso e' innocuo.

Questo modulo e' riusato sia da main.py (full_flow, flusso completo) sia da gui.py
(scenari singoli). Vale la Regola d'Oro: sola libreria cryptography, solo primitive
del corso; qui non c'e' nuova crittografia, solo orchestrazione.
"""
import copy
import logging
from dataclasses import dataclass

from crypto.pki import PKI
from actors.ca import UnisaCA
from actors.registrar import AuthUnisa
from actors.collector import VoteCollector
from actors.counter import VoteCounter
from actors.voter import Voter
from utils.payload import VotePayload, EncryptedBallot
from bulletin_board import PublicBulletin
import verifier

log = logging.getLogger("scenarios")

ELECTION_ID = "REF-UNISA-2026"
ELIGIBLE = ["0512100001", "0512100002", "0512100003", "0512100004"]  # aventi diritto
ELECTORATE_SIZE = len(ELIGIBLE)


@dataclass
class Env:
    """Ambiente di un'elezione: le quattro autorita' piu' il certificato di
    VoteCounter (che gli elettori usano per cifrare). Raggruppato per poter passare
    lo stato condiviso tra gli scenari di un flusso completo."""
    ca: UnisaCA
    registrar: AuthUnisa
    collector: VoteCollector
    counter: VoteCounter
    counter_cert: object


def sep(title: str) -> None:
    """Intestazione di fase, usata dal flusso completo per separare le sezioni."""
    print(f"\n{'=' * 12} {title} {'=' * 12}")


# --- costruzione dell'ambiente e helper di setup ---

def build_env() -> Env:
    """Ricostruisce da zero PKI, autorita' e secret sharing di un'elezione."""
    ca = UnisaCA()
    registrar = AuthUnisa(ca, ELIGIBLE)
    counter = VoteCounter(ca, threshold=3, shares_count=5)
    collector = VoteCollector(ca, registrar.cert)
    # Il certificato di VoteCounter e' il canale di distribuzione della sua PK:
    # gli elettori cifrano con questo, dopo averne verificato la catena fino a UnisaCA.
    return Env(ca, registrar, collector, counter, counter.cert)


def make_voter(env: Env, voter_id: str) -> Voter:
    """Crea un elettore con chiave personale certificata da UnisaCA."""
    priv, pub = PKI.generate_rsa_keypair()
    cert = env.ca.issue_certificate(voter_id, pub)
    return Voter(voter_id, priv, cert, env.ca, env.registrar, env.collector, env.counter_cert)


def cast_honest_votes(env: Env) -> dict:
    """Casta i tre voti onesti di riferimento e restituisce gli elettori per riuso."""
    alice = make_voter(env, "0512100001")
    charlie = make_voter(env, "0512100002")
    dario = make_voter(env, "0512100003")
    alice.cast_vote(ELECTION_ID, "SI")
    charlie.cast_vote(ELECTION_ID, "NO")
    dario.cast_vote(ELECTION_ID, "SI")
    return {"alice": alice, "charlie": charlie, "dario": dario}


def _setup_with_votes(env, voters):
    """Garantisce un ambiente con i voti onesti gia' espressi: precondizione degli
    scenari che operano su un'urna popolata (A1, A1b, scrutinio, verifica, A6)."""
    if env is None:
        env = build_env()
    if voters is None:
        voters = cast_honest_votes(env)
    return env, voters


def _tally(env):
    """Chiude l'urna (idempotente) e produce gli aggregati con la soglia raggiunta.
    Restituisce (board, result): la bacheca grezza e il risultato di scrutinio."""
    env.collector.close()
    board = env.collector.publish_board()
    shares = env.counter.get_shares()
    result = env.counter.tally(board, [shares[0], shares[2], shares[4]], ELECTION_ID)
    return board, result


def _assemble(env, board, result):
    """Assembla la bacheca pubblica (PublicBulletin) dai dati di urna e scrutinio."""
    return PublicBulletin.assemble(ELECTION_ID, ELECTORATE_SIZE, board, result, env.ca, env.registrar.cert)


# --- scenari ---

def honest_flow(env=None, voters=None):
    """Flusso onesto: tre aventi diritto votano correttamente (challenge-response,
    token anonimo, scheda cifrata legata al token)."""
    env = env or build_env()
    if voters is None:
        voters = cast_honest_votes(env)
    return env, voters


def attack_double_token(env=None, voters=None):
    """[A1] The Double (U.1): seconda richiesta di token per una matricola che ha
    gia' votato. AuthUnisa la rifiuta (registro per-matricola del rilascio)."""
    env, voters = _setup_with_votes(env, voters)
    log.info("[A1] The Double - secondo token per la stessa matricola (U.1)")
    voters["alice"].cast_vote(ELECTION_ID, "NO")  # gia' votato: il registrar rifiuta il secondo token


def attack_replay_ballot(env=None, voters=None):
    """[A1b] The Double (U.2): un attaccante ricattura dalla bacheca una scheda gia'
    registrata e la ripropone tale e quale. Il registro dei token spesi la blocca."""
    env, voters = _setup_with_votes(env, voters)
    log.info("[A1b] The Double - ripresentazione di una scheda gia' registrata (U.2)")
    rec = env.collector.records[voters["charlie"].seq]
    try:
        env.collector.submit_ballot(rec.to_ballot(), rec.to_token())
    except Exception as e:
        log.error(f"  BLOCCATO (registro spesi): {e}")


def attack_forged_cert(env=None, voters=None):
    """[A2] The Registrar/Outsider (A.2): identita' con certificato auto-firmato, non
    riconducibile a UnisaCA. La verifica di catena lo rifiuta gia' in autenticazione."""
    env = env or build_env()
    log.info("[A2] The Registrar/Outsider - identita' con certificato non emesso da UnisaCA (A.2)")
    fake_priv, fake_pub = PKI.generate_rsa_keypair()
    fake_cert = PKI.create_self_signed_ca("0512999999", fake_priv)  # auto-firmato: non risale a UnisaCA
    bob = Voter("0512999999", fake_priv, fake_cert, env.ca, env.registrar, env.collector, env.counter_cert)
    bob.cast_vote(ELECTION_ID, "SI")  # rifiutato: catena del certificato non valida


def attack_tamper_ciphertext(env=None, voters=None):
    """[A3] The Eavesdropper attivo (I.4): un avente diritto si autentica e prepara una
    scheda corretta; Mallory altera un bit di C in transito. La firma effimera su C
    (Encrypt-then-Authenticate) non torna piu' e VoteCollector respinge la scheda."""
    env = env or build_env()
    log.info("[A3] The Eavesdropper attivo - alterazione del ciphertext in transito (I.4)")
    nonce = env.registrar.issue_challenge("0512100004")
    d_voter = make_voter(env, "0512100004")
    sig_nonce = PKI.sign(d_voter.personal_private_key, nonce)
    eph_priv, eph_pub = PKI.generate_rsa_keypair()
    token = env.registrar.request_voting_token("0512100004", d_voter.personal_cert, sig_nonce, PKI.pub_to_pem(eph_pub))
    C = PKI.encrypt(env.counter_cert.public_key(), VotePayload(ELECTION_ID, "NO").to_bytes())
    auth = PKI.sign(eph_priv, C)
    C_tampered = C[:-1] + bytes([C[-1] ^ 0x01])  # Mallory cambia un bit di C
    try:
        env.collector.submit_ballot(EncryptedBallot(token.token_id, C_tampered, auth), token)
    except Exception as e:
        log.error(f"  BLOCCATO (Encrypt-then-Authenticate, firma effimera): {e}")


def attack_crl_hardfail(env=None, voters=None):
    """[A4] The Eavesdropper v.2 (§2.2.7): con il servizio CRL non disponibile lo stato
    di revoca non e' accertabile; la policy hard-fail rigetta anziche' accettare."""
    env = env or build_env()
    log.info("[A4] The Eavesdropper v.2 - hard-fail su CRL non disponibile (§2.2.7)")
    env.ca.crl_available = False
    eve = make_voter(env, "0512100004")
    eve.cast_vote(ELECTION_ID, "SI")  # rifiutato in hard-fail: stato di revoca non disponibile
    env.ca.crl_available = True
    log.info("  (servizio CRL ripristinato)")


def tally_scrutiny(env=None, voters=None):
    """[A5 + scrutinio] Chiusura urne e firma della radice; tentativo di apertura
    sotto-soglia (Shamir 2/3, bloccato); verifica individuale delle ricevute contro
    la radice firmata; scrutinio legittimo a soglia raggiunta; riconciliazione lato
    gestori. Restituisce (env, result) per il riuso nel flusso completo."""
    env, voters = _setup_with_votes(env, voters)

    log.info("[A5] The Counter - tentativo di apertura sotto-soglia (2 quote su 3)")
    env.collector.close()  # congela l'urna e firma la radice
    board = env.collector.publish_board()
    shares = env.counter.get_shares()
    try:
        env.counter.tally(board, shares[:2], ELECTION_ID)
    except Exception as e:
        log.error(f"  BLOCCATO (Shamir sotto-soglia): {e}")

    log.info("-> Verifica individuale delle ricevute (a urne chiuse, contro la radice firmata)")
    for v in voters.values():
        v.verify_receipt()

    log.info("-> Scrutinio legittimo (soglia 3/5 raggiunta)")
    result = env.counter.tally(board, [shares[0], shares[2], shares[4]], ELECTION_ID)
    print(f"   Aggregati: {result['aggregates']}  | validi: {result['valid_total']}  | "
          f"scarti: corrotte={result['discarded_corrupt']} fuori-dominio={result['discarded_domain']}")

    # Riconciliazione lato GESTORI (non e' una verifica pubblica): confronto tra i token
    # leciti emessi da AuthUnisa e i record effettivamente in urna. Vale emessi >= in_urna:
    # un avente diritto puo' ottenere il token senza completare una sottomissione valida
    # (es. [A3], token regolare ma scheda con C manomesso respinta). La differenza misura
    # le autorizzazioni non confluite in voto, non un'anomalia. Distinta dalle verifiche
    # universali di verifier.py, che usano i soli dati pubblici della bacheca.
    issued = env.registrar.issued_token_count()
    in_urn = len(board["records"])
    print(f"   Riconciliazione (lato gestori): token emessi={issued}, record in urna={in_urn}, "
          f"autorizzazioni non confluite in voto={issued - in_urn}")
    return env, result


def universal_verification(env=None, voters=None, bulletin=None):
    """[Verifica universale] Dai soli dati pubblici (PublicBulletin): catena dei
    certificati, radice firmata, ricostruzione dell'urna, autorizzazioni e legame,
    riconteggio, quorum 50%+1. Eseguibile da chiunque, senza fidarsi degli attori.
    Se `bulletin` e' fornito (flusso completo) lo riusa; altrimenti costruisce da
    solo l'elezione chiusa e scrutinata (esecuzione isolata dalla GUI)."""
    if bulletin is None:
        env, voters = _setup_with_votes(env, voters)
        board, result = _tally(env)
        bulletin = _assemble(env, board, result)
    res = verifier.verify_election(bulletin)
    verifier.print_report(res)
    print(f"\nQuorum (50%+1 di {ELECTORATE_SIZE} aventi diritto): "
          f"{'RAGGIUNTO' if res['quorum_reached'] else 'NON raggiunto'}")
    return bulletin


def attack_tamper_urn(env=None, voters=None, bulletin=None):
    """[A6] The Collector (I.1): a urne chiuse l'attaccante altera un ciphertext nella
    bacheca. La ricostruzione della radice dai record non torna piu' con la radice
    firmata: la verifica universale rileva la manomissione. Riusa `bulletin` se
    fornito, altrimenti costruisce da solo l'elezione chiusa e scrutinata."""
    if bulletin is None:
        env, voters = _setup_with_votes(env, voters)
        board, result = _tally(env)
        bulletin = _assemble(env, board, result)

    log.info("[A6] The Collector - manomissione dell'urna dopo la chiusura (I.1)")
    tampered = copy.deepcopy(bulletin)
    tampered.records[0].ciphertext = tampered.records[0].ciphertext[:-1] + b"\x00"
    res2 = verifier.verify_election(tampered)
    print(f"  Verifica su urna manomessa: {'PASS' if res2['passed'] else 'FAIL (manomissione rilevata)'}"
          f"  [urn_root_match={res2['checks']['urn_root_match']['ok']}]")


def full_flow():
    """Flusso completo end-to-end, equivalente all'originale run() di main.py:
    un unico ambiente attraversa preparazione, voto onesto, attacchi, chiusura,
    scrutinio e verifica universale, mantenendo la continuita' di stato tra le fasi."""
    sep("FASE 1 - PREPARAZIONE (PKI X.509, chiavi, secret sharing)")
    env = build_env()

    sep("FASE 2 - VOTO ONESTO (challenge-response + scheda cifrata)")
    voters = cast_honest_votes(env)

    sep("FASE 3 - ATTACCHI (threat model WP3, percorsi reali)")
    for attack in (attack_double_token, attack_replay_ballot, attack_forged_cert,
                   attack_tamper_ciphertext, attack_crl_hardfail):
        print()  # riga vuota di separazione tra gli attacchi
        attack(env, voters)

    sep("FASE 4 - CHIUSURA URNE E SCRUTINIO")
    env, result = tally_scrutiny(env, voters)

    sep("FASE 5 - VERIFICA UNIVERSALE (chiunque, da dati pubblici)")
    # La bacheca si costruisce una sola volta dal risultato gia' scrutinato e si
    # riusa per la verifica e per l'attacco A6 (niente riscrutinio ridondante).
    bulletin = _assemble(env, env.collector.publish_board(), result)
    universal_verification(env, voters, bulletin=bulletin)
    print()
    attack_tamper_urn(env, voters, bulletin=bulletin)


# Catalogo per la GUI: (id, etichetta, descrizione, funzione). L'ordine e' quello di
# presentazione e di esecuzione naturale. Le funzioni hanno tutte firma scenario(),
# eseguibili senza argomenti su un ambiente fresco.
SCENARIOS = [
    ("honest", "Flusso onesto",
     "Tre aventi diritto votano correttamente (challenge-response, token anonimo, scheda cifrata).",
     honest_flow),
    ("a1", "[A1] Doppio token (U.1)",
     "Seconda richiesta di token per una matricola che ha gia' votato: rifiutata da AuthUnisa.",
     attack_double_token),
    ("a1b", "[A1b] Ripresentazione scheda (U.2)",
     "Una scheda gia' in urna viene riproposta tale e quale: bloccata dal registro dei token spesi.",
     attack_replay_ballot),
    ("a2", "[A2] Certificato non emesso da UnisaCA (A.2)",
     "Identita' con certificato auto-firmato: rifiutata perche' la catena non risale alla CA.",
     attack_forged_cert),
    ("a3", "[A3] Alterazione del ciphertext in transito (I.4)",
     "Mallory altera un bit di C: la firma effimera su C non torna e VoteCollector respinge la scheda.",
     attack_tamper_ciphertext),
    ("a4", "[A4] Hard-fail su CRL non disponibile (2.2.7)",
     "Con il servizio CRL irraggiungibile lo stato di revoca non e' accertabile: si rigetta.",
     attack_crl_hardfail),
    ("tally", "[A5] Chiusura e scrutinio",
     "Chiusura urne, apertura sotto-soglia bloccata, verifica ricevute, scrutinio legittimo, riconciliazione.",
     tally_scrutiny),
    ("verify", "Verifica universale e quorum",
     "Verifica pubblica dai soli dati di bacheca (catena, radice, riconteggio) e calcolo del quorum.",
     universal_verification),
    ("a6", "[A6] Manomissione urna post-chiusura (I.1)",
     "Alterazione di un ciphertext a urne chiuse: rilevata dalla ricostruzione della radice Merkle.",
     attack_tamper_urn),
    ("full", "Flusso completo (tutto in sequenza)",
     "Esecuzione end-to-end equivalente al main: preparazione, voto, attacchi, scrutinio, verifica.",
     full_flow),
]
