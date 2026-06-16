# gui.py
"""GUI minimale per l'esecuzione on-demand degli scenari (WP4).

Interfaccia essenziale (libreria standard tkinter, nessuna dipendenza aggiuntiva,
coerente con il vincolo "sola libreria cryptography" del codice): una lista di
caselle, una per scenario, da cui scegliere cosa eseguire senza lanciare l'intero
main. Ogni scenario gira nel suo ambiente fresco (vedi scenarios.py) e in qualsiasi
ordine. L'output testuale prodotto dagli attori — sia via logging sia via print —
viene catturato e mostrato nell'area di log.

L'esecuzione avviene in un thread separato per non bloccare la finestra (la
generazione delle chiavi RSA dura qualche centinaio di millisecondi); le righe di
output sono passate alla UI tramite una coda drenata periodicamente con after().
"""
import logging
import queue
import sys
import threading
import tkinter as tk
from tkinter import ttk
from tkinter import scrolledtext

import scenarios

# Sentinella di fine esecuzione inviata dal worker alla coda della UI.
_DONE = object()


class _QueueWriter:
    """Oggetto file-like che instrada il testo scritto in una coda. Sostituisce
    sys.stdout e fa da sink per un handler di logging, cosi' che print e log
    finiscano entrambi nell'area di log della GUI."""

    def __init__(self, q: "queue.Queue"):
        self._q = q

    def write(self, text):
        if text:
            self._q.put(text)

    def flush(self):  # richiesto dall'interfaccia file-like; nulla da svuotare
        pass


class App(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("VoteUnisa - Esecuzione scenari (WP4)")
        self.geometry("900x640")

        # Il logging del progetto e' a livello root: per catturarne gli INFO basta
        # abbassare la soglia del root logger (di default WARNING) e collegare un
        # handler solo durante l'esecuzione. Non si chiama setup_logging per non
        # aggiungere un handler verso stderr: tutto l'output deve confluire nella GUI.
        logging.getLogger().setLevel(logging.INFO)

        self._queue: "queue.Queue" = queue.Queue()
        self._vars = {}        # id scenario -> BooleanVar della casella
        self._running = False

        self._build_widgets()

    # --- costruzione dell'interfaccia ---

    def _build_widgets(self):
        intro = ttk.Label(
            self,
            text="Seleziona gli scenari da verificare ed esegui quelli scelti. "
                 "Ogni scenario parte da un ambiente pulito.",
            padding=(10, 8),
        )
        intro.pack(fill="x")

        # Elenco scenari con casella di selezione e descrizione.
        box = ttk.LabelFrame(self, text="Scenari", padding=8)
        box.pack(fill="x", padx=10, pady=(0, 8))
        box.columnconfigure(1, weight=1)
        for row, (sid, label, desc, _func) in enumerate(scenarios.SCENARIOS):
            var = tk.BooleanVar(value=False)
            self._vars[sid] = var
            ttk.Checkbutton(box, text=label, variable=var).grid(
                row=row, column=0, sticky="w", padx=(0, 8), pady=1)
            ttk.Label(box, text=desc, foreground="#555").grid(
                row=row, column=1, sticky="w", pady=1)

        # Barra dei comandi.
        cmd = ttk.Frame(self, padding=(10, 0))
        cmd.pack(fill="x")
        ttk.Button(cmd, text="Seleziona tutto", command=lambda: self._set_all(True)).pack(side="left")
        ttk.Button(cmd, text="Deseleziona", command=lambda: self._set_all(False)).pack(side="left", padx=4)
        self._run_btn = ttk.Button(cmd, text="Esegui selezionati", command=self._on_run)
        self._run_btn.pack(side="left", padx=4)
        ttk.Button(cmd, text="Pulisci log", command=self._clear_log).pack(side="left")

        # Area di log (sola lettura, monospaziata).
        self._log = scrolledtext.ScrolledText(self, wrap="word", height=20,
                                               font=("Consolas", 9), state="disabled")
        self._log.pack(fill="both", expand=True, padx=10, pady=8)

        # Barra di stato.
        self._status = ttk.Label(self, text="Pronto.", relief="sunken", anchor="w", padding=(6, 2))
        self._status.pack(fill="x", side="bottom")

    # --- comandi della UI ---

    def _set_all(self, value: bool):
        for var in self._vars.values():
            var.set(value)

    def _clear_log(self):
        self._log.configure(state="normal")
        self._log.delete("1.0", "end")
        self._log.configure(state="disabled")

    def _append(self, text: str):
        self._log.configure(state="normal")
        self._log.insert("end", text)
        self._log.see("end")
        self._log.configure(state="disabled")

    def _on_run(self):
        if self._running:
            return
        selected = [s for s in scenarios.SCENARIOS if self._vars[s[0]].get()]
        if not selected:
            self._status.configure(text="Nessuno scenario selezionato.")
            return
        self._running = True
        self._run_btn.configure(state="disabled")
        self._status.configure(text="Esecuzione in corso...")
        threading.Thread(target=self._worker, args=(selected,), daemon=True).start()
        self.after(50, self._drain)

    # --- esecuzione in background + cattura output ---

    def _worker(self, selected):
        """Eseguito in un thread: instrada logging e stdout nella coda, lancia in
        sequenza gli scenari scelti (ciascuno su ambiente fresco) e li isola dagli
        errori, cosi' che un'eccezione in uno non interrompa gli altri."""
        writer = _QueueWriter(self._queue)
        handler = logging.StreamHandler(writer)
        handler.setLevel(logging.INFO)
        handler.setFormatter(logging.Formatter("%(message)s"))
        root = logging.getLogger()
        old_stdout = sys.stdout
        root.addHandler(handler)
        sys.stdout = writer
        try:
            for sid, label, desc, func in selected:
                print(f"\n{'=' * 12} {label} {'=' * 12}")
                try:
                    func()  # firma scenario(): ambiente fresco, nessun argomento
                except Exception as e:  # noqa: BLE001 - si riporta qualsiasi errore nel log
                    print(f"[ERRORE scenario] {e}")
            print("\n--- Esecuzione terminata ---")
        finally:
            # Ripristino sempre stdout e rimuovo l'handler, anche in caso di errore.
            sys.stdout = old_stdout
            root.removeHandler(handler)
            self._queue.put(_DONE)

    def _drain(self):
        """Svuota la coda nell'area di log; si richiama finche' non arriva _DONE."""
        try:
            while True:
                item = self._queue.get_nowait()
                if item is _DONE:
                    self._running = False
                    self._run_btn.configure(state="normal")
                    self._status.configure(text="Pronto.")
                    return
                self._append(item)
        except queue.Empty:
            pass
        self.after(50, self._drain)


def main():
    App().mainloop()


if __name__ == "__main__":
    main()
