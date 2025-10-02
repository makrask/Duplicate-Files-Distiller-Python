#!/usr/bin/env python3
import os
import shutil
import hashlib
from pathlib import Path
from datetime import datetime
import time
import tkinter as tk
from tkinter import filedialog, messagebox
from tkinter import ttk
from tkinter import scrolledtext
import concurrent.futures

# --- Utility Functions ---

def select_folder(title: str, initial: str) -> Path:
    root = tk.Tk()
    root.withdraw()
    root.attributes("-topmost", True)
    folder = filedialog.askdirectory(title=title, initialdir=initial)
    root.destroy()
    if not folder:
        messagebox.showerror("Error", "No folder selected, exiting.")
        exit(1)
    return Path(folder)

def write_log(log_file: Path, message: str):
    ts = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    with log_file.open("a", encoding="utf-8") as f:
        f.write(f"{ts} - {message}\n")

def human_seconds(s: float) -> str:
    if s == float("inf"):
        return "unknown"
    if s < 60:
        return f"{s:.1f}s"
    m, sec = divmod(int(s), 60)
    h, m = divmod(m, 60)
    if h > 0:
        return f"{h}h {m}m {sec}s"
    return f"{m}m {sec}s"

# --- Safe wrappers for pool and filesystem operations ---

def safe_sha256_for_pool(pstr: str, block_size: int = 65536):
    # returns (path_str, hash|None, error|None)
    try:
        path = Path(pstr)
        hasher = hashlib.sha256()
        with path.open("rb") as f:
            for chunk in iter(lambda: f.read(block_size), b""):
                hasher.update(chunk)
        return (pstr, hasher.hexdigest(), None)
    except Exception as e:
        return (pstr, None, f"{type(e).__name__}: {e}")

def safe_mkdir(path: Path):
    try:
        path.mkdir(parents=True, exist_ok=True)
        return True, None
    except Exception as e:
        return False, f"{type(e).__name__}: {e}"

def safe_move(src: Path, dest: Path):
    try:
        shutil.move(str(src), str(dest))
        return True, None
    except Exception as e:
        return False, f"{type(e).__name__}: {e}"

def remove_empty_safe(path: Path, log_file: Path, notify):
    errors = 0
    try:
        for sub in path.iterdir():
            if sub.is_dir():
                errors += remove_empty_safe(sub, log_file, notify)
                # Attempt to delete if empty
                try:
                    is_empty = True
                    for _ in sub.iterdir():
                        is_empty = False
                        break
                    if is_empty:
                        try:
                            sub.rmdir()
                            write_log(log_file, f"Deleted empty folder: {sub}")
                        except Exception as e:
                            errors += 1
                            msg = f"CLEANUP ERROR: Folder deletion failed: {sub} | {type(e).__name__}: {e}"
                            notify(msg)
                            write_log(log_file, msg)
                except Exception as e:
                    # Inability to read contents
                    errors += 1
                    msg = f"CLEANUP ERROR: Folder read failure: {sub} | {type(e).__name__}: {e}"
                    notify(msg)
                    write_log(log_file, msg)
    except Exception as e:
        errors += 1
        msg = f"CLEANUP ERROR: Access failure: {path} | {type(e).__name__}: {e}"
        notify(msg)
        write_log(log_file, msg)
    return errors

# --- Main Processing Logic ---

def process_duplicates(assorted: Path, main_dir: Path, bin_dir: Path, log_file: Path,
                       update_progress, update_status, is_paused, is_stopped, pump_events):
    t_all = time.time()

    # Error/action counters
    prep_hash_errors = 0
    run_hash_errors = 0
    move_errors = 0
    mkdir_errors = 0
    cleanup_errors = 0
    moved = 0
    kept = 0
    stopped = False

    def wait_if_paused():
        # Waiting while pause is active, without blocking the UI
        showed = False
        while is_paused() and not is_stopped():
            if not showed:
                update_status("⏸ Pause active. Waiting for continuation...")
                showed = True
            pump_events()
            time.sleep(0.05)

    try:
        # Early stop check
        if is_stopped():
            stopped = True

        # 1) PREPARE: Main folder scanning
        if not stopped:
            update_status("PREPARE: Main folder scanning...")
            wait_if_paused()
            if is_stopped():
                stopped = True
            if not stopped:
                try:
                    main_files = [p for p in main_dir.rglob('*') if p.is_file()]
                    update_status(f"PREPARE: Found {len(main_files)} files in main folder")
                except Exception as e:
                    update_status(f"PREPARE ERROR: Scan failure main_dir | {type(e).__name__}: {e}")
                    main_files = []

        # 2) PREPARE: Main folder file hashing (safe)
        hash_to_paths: dict[str, list[Path]] = {}
        if not stopped:
            update_status("PREPARE: SHA-256 calculation for main folder files...")
            t_hash_main = time.time()
            if main_files:
                chunk = max(100, max(len(main_files) // 20, 1))
                with concurrent.futures.ProcessPoolExecutor() as exe:
                    for i, (pstr, h, err) in enumerate(exe.map(safe_sha256_for_pool, map(str, main_files)), 1):
                        wait_if_paused()
                        if is_stopped():
                            stopped = True
                            break
                        p = Path(pstr)
                        if h is not None:
                            hash_to_paths.setdefault(h, []).append(p)
                        else:
                            prep_hash_errors += 1
                            msg = f"PREPARE ERROR: Hashing failed: {p} | {err}"
                            update_status(msg)
                            write_log(log_file, msg)
                        if i % chunk == 0 or i == len(main_files):
                            elapsed = time.time() - t_hash_main
                            rate = i / elapsed if elapsed > 0 else 0
                            update_status(f"PREPARE: Hashed {i}/{len(main_files)} "
                                          f"({rate:.1f} files/sec.) | Errors: {prep_hash_errors}")
            if not stopped:
                update_status(f"PREPARE: Main folder hashing completed | Unique hashes: {len(hash_to_paths)} "
                              f"| Duration: {human_seconds(time.time() - t_hash_main)} | Errors: {prep_hash_errors}")

        # 3) RUN: Scan assorted
        if not stopped:
            update_status("RUN: Assorted folder scanning...")
            wait_if_paused()
            if is_stopped():
                stopped = True
            if not stopped:
                try:
                    assorted_files = [p for p in assorted.rglob('*') if p.is_file()]
                except Exception as e:
                    update_status(f"RUN ERROR: Assorted scan failure | {type(e).__name__}: {e}")
                    assorted_files = []
                total = len(assorted_files)
                update_status(f"RUN: Found {total} files to check")
                update_progress(0, total)
            else:
                assorted_files, total = [], 0
        else:
            assorted_files, total = [], 0

        # 4) RUN: Hash & compare & move (safe)
        if not stopped and total > 0:
            done = 0
            t_run = time.time()
            chunk2 = max(100, max(total // 20, 1))
            update_status("RUN: Start processing...")
            with concurrent.futures.ProcessPoolExecutor() as exe:
                for idx, (pstr, file_hash, err) in enumerate(exe.map(safe_sha256_for_pool, map(str, assorted_files)), 1):
                    wait_if_paused()
                    if is_stopped():
                        stopped = True
                        break
                    src = Path(pstr)
                    if file_hash is None:
                        run_hash_errors += 1
                        msg = f"RUN ERROR: Hashing failed: {src} | {err}"
                        update_status(msg)
                        write_log(log_file, msg)
                        kept += 1  # we cannot confirm duplicate -> we keep 
                    else:
                        if file_hash in hash_to_paths:
                            rel = src.relative_to(assorted)
                            dest_dir = bin_dir / rel.parent
                            ok, mkerr = safe_mkdir(dest_dir)
                            if not ok:
                                mkdir_errors += 1
                                msg = f"RUN ERROR: mkdir failed: {dest_dir} | {mkerr}"
                                update_status(msg)
                                write_log(log_file, msg)
                                kept += 1
                            else:
                                dest = dest_dir / src.name
                                ok, merr = safe_move(src, dest)
                                if ok:
                                    moved += 1
                                    write_log(log_file, f"Moved: {src} → {dest}")
                                else:
                                    move_errors += 1
                                    msg = f"RUN ERROR: move failed: {src} → {dest} | {merr}"
                                    update_status(msg)
                                    write_log(log_file, msg)
                                    kept += 1
                        else:
                            kept += 1

                    done += 1
                    update_progress(done, total)

                    if idx % chunk2 == 0 or idx == total:
                        elapsed = time.time() - t_run
                        rate = idx / elapsed if elapsed > 0 else 0
                        remain = total - idx
                        eta = remain / rate if rate > 0 else float("inf")
                        update_status(
                            f"RUN: {idx}/{total} | Moved: {moved} | Kept: {kept} "
                            f"| Hash errors: {run_hash_errors} | Move errors: {move_errors} | Mkdir errors: {mkdir_errors} "
                            f"| Rate: {rate:.1f}/s | Elapsed: {human_seconds(elapsed)} | ETA: {human_seconds(eta)}"
                        )

        # 5) CLEANUP or Stop
        if stopped:
            update_status("🛑 Stop execution at user request. Bypass cleanup.")
            total_time = human_seconds(time.time() - t_all)
            update_status(
                f"FINISH: Stopped | Moved: {moved} | Kept: {kept} "
                f"| Prep hash errors: {prep_hash_errors} | Run hash errors: {run_hash_errors} "
                f"| Move errors: {move_errors} | Mkdir errors: {mkdir_errors} "
                f"| Total time: {total_time}"
            )
            messagebox.showinfo("Info", "Stopped by user.")
            return

        update_status("CLEANUP: Remove empty folders...")
        cleanup_errors += remove_empty_safe(assorted, log_file, update_status)

        total_time = human_seconds(time.time() - t_all)
        update_status(
            f"FINISH: Completed | Moved: {moved} | Kept: {kept} "
            f"| Prep hash errors: {prep_hash_errors} | Run hash errors: {run_hash_errors} "
            f"| Move errors: {move_errors} | Mkdir errors: {mkdir_errors} | Cleanup errors: {cleanup_errors} "
            f"| Total time: {total_time}"
        )
        messagebox.showinfo("Info", "Done!!!")

    except Exception as e:
        # Any unexpected error at the upper level
        msg = f"FATAL (non-stop): {type(e).__name__}: {e}"
        update_status(msg)
        write_log(log_file, msg)
        messagebox.showwarning("Warning", f"Completed with a critical error: {e}")

# --- GUI with Progress Bar, Text Console, and Control Buttons ---

class DistillFilesApp(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("Duplicate Files Distiller")
        self.geometry("600x420")
        self.resizable(True, True)

        # Control flags
        self.pause_requested = False
        self.stop_requested = False

        # Folder selections
        self.assorted = tk.StringVar()
        self.main_dir  = tk.StringVar()
        self.recycle   = tk.StringVar()

        def make_row(label, var, row):
            tk.Label(self, text=label).grid(column=0, row=row, padx=8, pady=4, sticky="w")
            tk.Entry(self, textvariable=var, width=60).grid(column=1, row=row, columnspan=2, sticky="we")
            tk.Button(self, text="Browse",
                      command=lambda v=var,l=label: v.set(str(select_folder(l, v.get() or os.getcwd())))) \
                .grid(column=3, row=row, padx=4)

        make_row("Assorted Folder:", self.assorted, 0)
        make_row("Main Folder:",     self.main_dir,  1)
        make_row("Recycle Bin:",     self.recycle,   2)

        # Progress bar
        self.progress = ttk.Progressbar(self, length=560, mode="determinate")
        self.progress.grid(column=0, row=3, columnspan=4, pady=8, padx=8, sticky="we")

        # Fixed button width
        btn_width = 22
        
        # Control buttons: Run / Pause / Stop        
        self.btn_run = tk.Button(self, text="🧪 Distill Files", command=self.start, width=btn_width)
        self.btn_run.grid(column=0, row=4, columnspan=1, pady=4, padx=8, sticky="ns")

        self.btn_pause = tk.Button(self, text="⏸️ Pause", command=self.toggle_pause, state="disabled", width=btn_width)
        self.btn_pause.grid(column=1, row=4, columnspan=1, pady=4, padx=8, sticky="ns")

        self.btn_stop = tk.Button(self, text="🛑 Stop", command=self.request_stop, state="disabled", width=btn_width)
        self.btn_stop.grid(column=2, row=4, columnspan=1, pady=4, padx=8, sticky="ns")

        # Spacer for alignment
        tk.Label(self, text="").grid(column=3, row=4, pady=4, padx=8, sticky="we")

        # Text console for alphanumeric status messages
        self.console = scrolledtext.ScrolledText(self, width=80, height=12, state="disabled")
        self.console.grid(column=0, row=5, columnspan=4, padx=8, pady=8, sticky="nsew")

        # Grid weights (optional)
        self.grid_columnconfigure(1, weight=1)
        self.grid_rowconfigure(5, weight=1)

    def log(self, msg: str):
        ts = datetime.now().strftime("%H:%M:%S")
        self.console.configure(state="normal")
        self.console.insert("end", f"{ts} | {msg}\n")
        self.console.see("end")
        self.console.configure(state="disabled")
        self.update_idletasks()

    def toggle_pause(self):
        self.pause_requested = not self.pause_requested
        label = "Resume" if self.pause_requested else "Pause"
        self.btn_pause.configure(text=label)
        self.log("⏸ Pause activated" if self.pause_requested else "▶ Resume")

    def request_stop(self):
        self.stop_requested = True
        # If it was paused, we allow it to exit the pause loop
        self.pause_requested = False
        self.btn_pause.configure(text="Pause")
        self.log("🛑 Stop requested by user.")

    def pump_events(self):
        # Processing pending events to keep the UI responsive
        try:
            self.update()
        except tk.TclError:
            pass

    def is_paused(self) -> bool:
        return self.pause_requested

    def is_stopped(self) -> bool:
        return self.stop_requested

    def on_processing_started(self):
        self.btn_run.configure(state="disabled")
        self.btn_pause.configure(state="normal", text="Pause")
        self.btn_stop.configure(state="normal")
        self.pause_requested = False
        self.stop_requested = False

    def on_processing_done(self):
        self.btn_run.configure(state="normal")
        self.btn_pause.configure(state="disabled", text="Pause")
        self.btn_stop.configure(state="disabled")

    def start(self):
        self.progress["value"] = 0
        self.update_idletasks()

        u = Path(self.assorted.get())
        v = Path(self.main_dir.get())
        r = Path(self.recycle.get())
        ts_log_name = datetime.now().strftime("%Y%m%d%H%M%S_") + "move-log.txt"
        log = Path(__file__).parent / ts_log_name
        log.touch(exist_ok=True)
        r.mkdir(parents=True, exist_ok=True)

        def update_progress(done, total):
            self.progress["maximum"] = max(total, 1)
            self.progress["value"] = done
            self.update_idletasks()

        self.on_processing_started()

        def run():
            try:
                process_duplicates(
                    assorted=u,
                    main_dir=v,
                    bin_dir=r,
                    log_file=log,
                    update_progress=update_progress,
                    update_status=self.log,
                    is_paused=self.is_paused,
                    is_stopped=self.is_stopped,
                    pump_events=self.pump_events,
                )
            finally:
                self.on_processing_done()

        # Slight delay to update the UI first
        self.after(100, run)

if __name__ == "__main__":
    DistillFilesApp().mainloop()
