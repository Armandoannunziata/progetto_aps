# Project_work/ — Traccia e documenti WP1/WP2/WP3

Questa cartella contiene due cose con ruoli DIVERSI:
- la **TRACCIA** del project work: i requisiti, gli attori, le minacce e i criteri
  di valutazione a cui ogni WP deve rispondere puntualmente;
- il **DOCX con i nostri WP1/WP2/WP3** (versione quasi definitiva): è la specifica
  VINCOLANTE per il codice in `../elezioni_unisa/` ed è il documento da REVISIONARE.

## Compito su questi documenti: REVISIONE, non riscrittura
I tre WP sono praticamente completi. Su di essi NON si riscrive a ruota libera. Il
lavoro è:
1. **Impronte da LLM** — segnala (senza riscrivere d'iniziativa) frasi e tic
   tipici: "In conclusione", "È importante notare", "Come abbiamo visto",
   "Certamente", introduzioni prolisse, entusiasmo, ridondanze, elenchi gratuiti.
   Proponi una versione asciutta e impersonale e attendi conferma.
2. **Coerenza interna** — verifica che WP1, WP2 e WP3 non si contraddicano:
   proprietà dichiarate vs meccanismi scelti vs analisi svolta. Esempio noto da
   correggere: in §2.2.8 la foglia dell'urna è `H(H(C)‖H(token_id))`, non `H(C)`;
   la frase del verificatore va allineata a questa forma.
3. **Coerenza con la traccia** — verifica che ogni richiesta della traccia trovi
   risposta nei WP, con particolare attenzione alla motivazione dei compromessi.
4. **Coerenza con il codice** — le scelte dei WP devono combaciare con
   `../elezioni_unisa/`; se divergono, segnala il disallineamento (non sanare il
   documento per "far quadrare" il codice senza conferma).

## Modalità
Procedi in **modalità di pianificazione**: presenta le modifiche proposte come
elenco puntuale o diff, NON applicarle finché non confermo. Per una revisione
sistematica di un singolo documento puoi usare il comando `/revisione`.

## Stile
Accademico, tecnico, asciutto, impersonale; rigore formale; niente fronzoli.
Non introdurre tecniche o tecnologie fuori dal perimetro del corso
(@../perimetro_corso.md).
