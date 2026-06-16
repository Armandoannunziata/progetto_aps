# main.py
"""Simulazione end-to-end del referendum (WP4).

Esegue il flusso onesto, una batteria di attacchi del threat model di WP3
attraverso i PERCORSI REALI del codice, la chiusura con firma della radice, lo
scrutinio verificabile e la verifica universale con calcolo del quorum.
"""
import copy
import logging

from utils.logger import setup_logging
from crypto.pki import PKI
from actors.ca import UnisaCA
from actors.registrar import AuthUnisa
from actors.collector import VoteCollector
from actors.counter import VoteCounter
from actors.voter import Voter
from utils.payload import VotePayload, EncryptedBallot
from bulletin_board import PublicBulletin
import verifier

setup_logging(logging.INFO)
log = logging.getLogger("main")

ELECTION_ID = "REF-UNISA-2026"
ELIGIBLE = ["0512100001", "0512100002", "0512100003", "0512100004"]  # aventi diritto
ELECTORATE_SIZE = len(ELIGIBLE)


def sep(title):
    print(f"\n{'=' * 12} {title} {'=' * 12}")


def make_voter(voter_id, ca, registrar, collector, counter_cert):
    priv, pub = PKI.generate_rsa_keypair()
    cert = ca.issue_certificate(voter_id, pub)
    return Voter(voter_id, priv, cert, ca, registrar, collector, counter_cert)


def run():
    sep("FASE 1 - PREPARAZIONE (PKI X.509, chiavi, secret sharing)")
    ca = UnisaCA()
    registrar = AuthUnisa(ca, ELIGIBLE)
    counter = VoteCounter(ca, threshold=3, shares_count=5)
    collector = VoteCollector(ca, registrar.cert)
    counter_cert = counter.cert  # distribuito tramite certificato (gli elettori cifrano con questo)

    sep("FASE 2 - VOTO ONESTO (challenge-response + scheda cifrata)")
    alice = make_voter("0512100001", ca, registrar, collector, counter_cert)
    charlie = make_voter("0512100002", ca, registrar, collector, counter_cert)
    dario = make_voter("0512100003", ca, registrar, collector, counter_cert)
    alice.cast_vote(ELECTION_ID, "SI")
    charlie.cast_vote(ELECTION_ID, "NO")
    dario.cast_vote(ELECTION_ID, "SI")

    sep("FASE 3 - ATTACCHI (threat model WP3, percorsi reali)")

    log.info("\n[A1] The Double - secondo token per la stessa matricola (U.1)")
    alice.cast_vote(ELECTION_ID, "NO")  # gia' votato: il registrar rifiuta il secondo token

    log.info("\n[A1b] The Double - ripresentazione di una scheda gia' registrata (U.2)")
    # Un attaccante ricattura la scheda di Charlie dalla bacheca e la ripropone tale e quale.
    rec = collector.records[charlie.seq]
    try:
        collector.submit_ballot(rec.to_ballot(), rec.to_token())
    except Exception as e:
        log.error(f"  BLOCCATO (registro spesi): {e}")

    log.info("\n[A2] The Registrar/Outsider - identita' con certificato non emesso da UnisaCA (A.2)")
    fake_priv, fake_pub = PKI.generate_rsa_keypair()
    fake_cert = PKI.create_self_signed_ca("0512999999", fake_priv)  # auto-firmato: non risale a UnisaCA
    bob = Voter("0512999999", fake_priv, fake_cert, ca, registrar, collector, counter_cert)
    bob.cast_vote(ELECTION_ID, "SI")  # rifiutato: catena del certificato non valida

    log.info("\n[A3] The Eavesdropper attivo - alterazione del ciphertext in transito (I.4)")
    # Un avente diritto si autentica e prepara una scheda corretta; Mallory altera C prima dell'invio.
    nonce = registrar.issue_challenge("0512100004")
    d_voter = make_voter("0512100004", ca, registrar, collector, counter_cert)
    sig_nonce = PKI.sign(d_voter.personal_private_key, nonce)
    eph_priv, eph_pub = PKI.generate_rsa_keypair()
    token = registrar.request_voting_token("0512100004", d_voter.personal_cert, sig_nonce, PKI.pub_to_pem(eph_pub))
    C = PKI.encrypt(counter_cert.public_key(), VotePayload(ELECTION_ID, "NO").to_bytes())
    auth = PKI.sign(eph_priv, C)
    C_tampered = C[:-1] + bytes([C[-1] ^ 0x01])  # Mallory cambia un bit di C
    try:
        collector.submit_ballot(EncryptedBallot(token.token_id, C_tampered, auth), token)
    except Exception as e:
        log.error(f"  BLOCCATO (Encrypt-then-Authenticate, firma effimera): {e}")

    log.info("\n[A4] The Eavesdropper v.2 - hard-fail su CRL non disponibile (§2.2.7)")
    ca.crl_available = False
    eve = make_voter("0512100004", ca, registrar, collector, counter_cert)  # gia' usato sopra: comunque rifiutato prima per CRL
    eve.cast_vote(ELECTION_ID, "SI")  # rifiutato in hard-fail: stato di revoca non disponibile
    ca.crl_available = True
    log.info("  (servizio CRL ripristinato)")

    sep("FASE 4 - CHIUSURA URNE E SCRUTINIO")
    log.info("\n[A5] The Counter - tentativo di apertura sotto-soglia (2 quote su 3)")
    collector.close()  # congela l'urna e firma la radice
    board = collector.publish_board()
    shares = counter.get_shares()
    try:
        counter.tally(board, shares[:2], ELECTION_ID)
    except Exception as e:
        log.error(f"  BLOCCATO (Shamir sotto-soglia): {e}")

    log.info("\n-> Verifica individuale delle ricevute (a urne chiuse, contro la radice firmata)")
    for v in (alice, charlie, dario):
        v.verify_receipt()

    log.info("\n-> Scrutinio legittimo (soglia 3/5 raggiunta)")
    result = counter.tally(board, [shares[0], shares[2], shares[4]], ELECTION_ID)
    print(f"   Aggregati: {result['aggregates']}  | validi: {result['valid_total']}  | "
          f"scarti: corrotte={result['discarded_corrupt']} fuori-dominio={result['discarded_domain']}")

    # Riconciliazione lato GESTORI (non e' una verifica pubblica): confronto tra i
    # token leciti emessi da AuthUnisa e i record effettivamente presenti in urna.
    # E' un controllo interno di coerenza amministrativa basato sullo stato privato
    # di AuthUnisa, DISTINTO dalle verifiche universali di verifier.py (che si
    # fondano sui soli dati pubblici della bacheca e non possono leggere quanti
    # token l'autorita' ha rilasciato). In generale vale emessi >= in_urna: un
    # avente diritto puo' ottenere il token ma non completare una sottomissione
    # valida; qui [A3] ha ricevuto un token regolare ma la sua scheda con C
    # manomesso e' stata respinta da VoteCollector, quindi una differenza non e'
    # un'anomalia ma misura quante autorizzazioni non si sono tradotte in voto.
    issued = registrar.issued_token_count()
    in_urn = len(board["records"])
    print(f"   Riconciliazione (lato gestori): token emessi={issued}, record in urna={in_urn}, "
          f"autorizzazioni non confluite in voto={issued - in_urn}")

    sep("FASE 5 - VERIFICA UNIVERSALE (chiunque, da dati pubblici)")
    bulletin = PublicBulletin.assemble(ELECTION_ID, ELECTORATE_SIZE, board, result, ca, registrar.cert)
    res = verifier.verify_election(bulletin)
    verifier.print_report(res)
    print(f"\nQuorum (50%+1 di {ELECTORATE_SIZE} aventi diritto): "
          f"{'RAGGIUNTO' if res['quorum_reached'] else 'NON raggiunto'}")

    log.info("\n[A6] The Collector - manomissione dell'urna dopo la chiusura (I.1)")
    # L'attaccante altera un ciphertext nella bacheca; la verifica universale lo rileva.
    tampered = copy.deepcopy(bulletin)
    tampered.records[0].ciphertext = tampered.records[0].ciphertext[:-1] + b"\x00"
    res2 = verifier.verify_election(tampered)
    print(f"  Verifica su urna manomessa: {'PASS' if res2['passed'] else 'FAIL (manomissione rilevata)'}"
          f"  [urn_root_match={res2['checks']['urn_root_match']['ok']}]")


if __name__ == "__main__":
    run()
