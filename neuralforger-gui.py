#!/usr/bin/env python3
"""
Neural Forger - GUI Interface
ML-Powered SSRF Detection Framework

Graphical interface for Neural Forger + SSRFfinder.
Requires: Python 3, tkinter (pre-installed on most Linux distros).
Run: python3 neuralforger-gui.py
"""

import tkinter as tk
from tkinter import ttk, scrolledtext, filedialog, messagebox
import subprocess
import threading
import os
import tempfile
import signal
import sys

# ============================================================================
# Config
# ============================================================================

VERSION = "1.0.0"
TOOL_NAME = "Neural Forger"
MARKERS = ["SSRF", "***", "INJECT", "FUZZ"]
BASE_DIR = os.path.dirname(os.path.abspath(__file__))

BG = "#2b2b2b"
BG2 = "#363636"
BG_INPUT = "#3c3c3c"
FG = "#e8e8e8"
FG_DIM = "#aaaaaa"
FG_ACCENT = "#a0d0a0"
BORDER = "#606060"
FONT = ("Courier", 10)
FONT_SM = ("Courier", 9)
FONT_TITLE = ("Courier", 14, "bold")
FONT_SUB = ("Courier", 9)


# ============================================================================
# Responsive Grid Helper
# ============================================================================

class ResponsiveFrame(tk.Frame):
    """
    A frame that re-lays out its child 'field rows' based on width.
    Wide  -> fields side by side (grid columns).
    Narrow -> fields stacked vertically.
    """

    def __init__(self, master, cols_wide=2, **kw):
        kw.setdefault("bg", BG)
        super().__init__(master, **kw)
        self._rows = []
        self._cols_wide = cols_wide
        self._threshold = 700
        self._current_cols = 0
        self.bind("<Configure>", self._on_resize)

    def add_field(self, widget):
        self._rows.append(widget)

    def relayout(self):
        w = self.winfo_width()
        cols = self._cols_wide if w >= self._threshold else 1
        if cols == self._current_cols:
            return
        self._current_cols = cols

        for widget in self._rows:
            widget.grid_forget()

        for i, widget in enumerate(self._rows):
            r = i // cols
            c = i % cols
            widget.grid(row=r, column=c, sticky="ew", padx=4, pady=2)

        for c in range(cols):
            self.columnconfigure(c, weight=1)

    def _on_resize(self, event):
        self.relayout()


# ============================================================================
# Section Frame (fieldset style)
# ============================================================================

class Section(tk.LabelFrame):
    def __init__(self, master, title, **kw):
        super().__init__(
            master,
            text=f"  [ {title} ]  ",
            font=FONT_SM,
            fg=FG_DIM,
            bg=BG,
            bd=1,
            relief="solid",
            highlightbackground=BORDER,
            highlightthickness=0,
            padx=8,
            pady=6,
            **kw,
        )


# ============================================================================
# Field Builders
# ============================================================================

def make_row(parent, label_text, widget_factory, **grid_kw):
    """Create a label + widget row inside a small frame."""
    frame = tk.Frame(parent, bg=BG)

    lbl = tk.Label(frame, text=label_text, font=FONT_SM, fg=FG_DIM, bg=BG,
                   anchor="w", width=20)
    lbl.pack(side="left", padx=(0, 4))

    widget = widget_factory(frame)
    widget.pack(side="left", fill="x", expand=True)

    return frame, widget


def make_entry(parent, placeholder="", width=30):
    e = tk.Entry(parent, font=FONT_SM, bg=BG_INPUT, fg=FG, insertbackground=FG,
                 relief="solid", bd=1, highlightthickness=0, width=width)
    return e


def make_combo(parent, values, default=0, width=20):
    style_name = f"Dark.TCombobox"
    c = ttk.Combobox(parent, values=values, state="readonly", width=width, font=FONT_SM)
    c.current(default)
    return c


def make_check(parent, text):
    var = tk.BooleanVar(value=False)
    cb = tk.Checkbutton(parent, text=text, variable=var, font=FONT_SM,
                        fg=FG, bg=BG, selectcolor=BG_INPUT,
                        activebackground=BG, activeforeground=FG,
                        highlightthickness=0, anchor="w")
    return cb, var


# ============================================================================
# Main Application
# ============================================================================

class NeuralForgerGUI:
    def __init__(self, root):
        self.root = root
        self.root.title(f"{TOOL_NAME} v{VERSION}")
        self.root.configure(bg=BG)
        self.root.minsize(600, 500)
        self.process = None

        # Try to maximize or set large geometry
        try:
            self.root.state("zoomed")
        except Exception:
            self.root.geometry("1100x750")

        # Style for comboboxes
        self._setup_style()

        # Build UI
        self._build_header()
        self._build_main()
        self._build_statusbar()

        # Update command on any change
        self.root.after(200, self._schedule_update)

    # ----------------------------------------------------------------
    # Style
    # ----------------------------------------------------------------

    def _setup_style(self):
        style = ttk.Style()
        style.theme_use("clam")
        style.configure("Dark.TCombobox",
                        fieldbackground=BG_INPUT,
                        background=BG2,
                        foreground=FG,
                        arrowcolor=FG_DIM,
                        bordercolor=BORDER,
                        lightcolor=BORDER,
                        darkcolor=BORDER,
                        selectbackground=BG2,
                        selectforeground=FG)
        style.map("Dark.TCombobox",
                   fieldbackground=[("readonly", BG_INPUT)],
                   foreground=[("readonly", FG)],
                   selectbackground=[("readonly", BG_INPUT)],
                   selectforeground=[("readonly", FG)])
        style.configure("Dark.TCombobox", font=FONT_SM)

    # ----------------------------------------------------------------
    # Header
    # ----------------------------------------------------------------

    def _build_header(self):
        hdr = tk.Frame(self.root, bg=BG, pady=8)
        hdr.pack(fill="x")

        tk.Label(hdr, text=TOOL_NAME.upper(), font=FONT_TITLE,
                 fg=FG, bg=BG).pack()
        tk.Label(hdr, text=f"ML-Powered SSRF Detection Framework  v{VERSION}",
                 font=FONT_SUB, fg=FG_DIM, bg=BG).pack()

        sep = tk.Frame(self.root, bg=BORDER, height=1)
        sep.pack(fill="x")

    # ----------------------------------------------------------------
    # Main Area (PanedWindow: top=options, bottom=editor+output)
    # ----------------------------------------------------------------

    def _build_main(self):
        pw = tk.PanedWindow(self.root, orient="vertical", bg=BG,
                            sashwidth=4, sashrelief="flat",
                            bd=0, opaqueresize=True)
        pw.pack(fill="both", expand=True)

        # -- Top: Options --
        top_frame = tk.Frame(pw, bg=BG)
        pw.add(top_frame, stretch="always")

        canvas = tk.Canvas(top_frame, bg=BG, highlightthickness=0, bd=0)
        scrollbar = tk.Scrollbar(top_frame, orient="vertical", command=canvas.yview,
                                 bg=BG2, troughcolor=BG, highlightthickness=0)
        self.options_frame = tk.Frame(canvas, bg=BG)

        self.options_frame.bind("<Configure>",
                                lambda e: canvas.configure(scrollregion=canvas.bbox("all")))
        canvas_window = canvas.create_window((0, 0), window=self.options_frame, anchor="n")
        canvas.configure(yscrollcommand=scrollbar.set)

        # Center the options frame inside the canvas
        def _center_options(event):
            canvas_width = event.width
            canvas.itemconfigure(canvas_window, width=min(canvas_width, 1200))
            # re-center
            if canvas_width > 1200:
                x = (canvas_width - 1200) // 2
            else:
                x = 0
            canvas.coords(canvas_window, x, 0)
        canvas.bind("<Configure>", _center_options)

        scrollbar.pack(side="right", fill="y")
        canvas.pack(side="left", fill="both", expand=True)

        # Mouse wheel scroll
        def _on_mousewheel(event):
            canvas.yview_scroll(int(-1 * (event.delta / 120 if event.delta else
                                           (-1 if event.num == 4 else 1))), "units")

        canvas.bind_all("<Button-4>", _on_mousewheel)
        canvas.bind_all("<Button-5>", _on_mousewheel)

        self._build_options(self.options_frame)

        # -- Bottom: Editor + Output --
        bottom_frame = tk.Frame(pw, bg=BG)
        pw.add(bottom_frame, stretch="always")
        self._build_editor(bottom_frame)

    # ----------------------------------------------------------------
    # Options Sections
    # ----------------------------------------------------------------

    def _build_options(self, parent):
        pad = {"fill": "x", "padx": 8, "pady": 4}

        # ---- MODE ----
        sec = Section(parent, "MODE")
        sec.pack(**pad)
        grid = ResponsiveFrame(sec, cols_wide=2)
        grid.pack(fill="x")

        f, self.combo_mode = make_row(grid, "Operation:", lambda p: make_combo(
            p, ["Injection Testing (-p)", "ML Inspection Only (-i)"], 0))
        grid.add_field(f)
        self.combo_mode.bind("<<ComboboxSelected>>", lambda e: self._on_change())

        f, self.combo_ml = make_row(grid, "Use ML Analysis:", lambda p: make_combo(
            p, ["Yes (Neural Forger)", "No (SSRFfinder only)"], 0))
        grid.add_field(f)
        self.combo_ml.bind("<<ComboboxSelected>>", lambda e: self._on_change())

        self.param_frame, self.entry_param = make_row(
            grid, "Target Parameter:", lambda p: make_entry(p, "url, callback, redirect"))
        grid.add_field(self.param_frame)
        self.entry_param.bind("<KeyRelease>", lambda e: self._on_change())

        grid.relayout()

        # ---- INPUT ----
        sec = Section(parent, "INPUT")
        sec.pack(**pad)
        grid = ResponsiveFrame(sec, cols_wide=2)
        grid.pack(fill="x")

        f, self.combo_source = make_row(grid, "Source:", lambda p: make_combo(
            p, ["Request Editor (below)", "Request File (-r)", "Direct URL (-u)"], 0))
        grid.add_field(f)
        self.combo_source.bind("<<ComboboxSelected>>", lambda e: self._on_change())

        self.file_frame = tk.Frame(grid, bg=BG)
        lbl = tk.Label(self.file_frame, text="File Path:", font=FONT_SM, fg=FG_DIM,
                       bg=BG, anchor="w", width=20)
        lbl.pack(side="left", padx=(0, 4))
        self.entry_file = make_entry(self.file_frame, "/path/to/request.txt")
        self.entry_file.pack(side="left", fill="x", expand=True)
        btn_browse = tk.Button(self.file_frame, text="...", font=FONT_SM, bg=BG2,
                               fg=FG, relief="solid", bd=1, highlightthickness=0,
                               command=self._browse_file, width=3)
        btn_browse.pack(side="left", padx=(4, 0))
        grid.add_field(self.file_frame)
        self.entry_file.bind("<KeyRelease>", lambda e: self._on_change())

        self.url_frame, self.entry_url = make_row(
            grid, "Target URL:", lambda p: make_entry(p, "http://target.com/api?url=SSRF"))
        grid.add_field(self.url_frame)
        self.entry_url.bind("<KeyRelease>", lambda e: self._on_change())

        grid.relayout()

        # ---- PAYLOADS ----
        self.sec_payloads = Section(parent, "PAYLOADS")
        self.sec_payloads.pack(**pad)
        grid = ResponsiveFrame(self.sec_payloads, cols_wide=2)
        grid.pack(fill="x")
        self._payload_grid = grid

        f, self.combo_strategy = make_row(grid, "Strategy:", lambda p: make_combo(
            p, ["ml-recommended", "all", "ml-only", "custom (wordlist)"], 0))
        grid.add_field(f)
        self.combo_strategy.bind("<<ComboboxSelected>>", lambda e: self._on_change())

        self.wl_frame, self.entry_wordlist = make_row(
            grid, "Wordlist File:", lambda p: make_entry(p, "/path/to/wordlist.txt"))
        grid.add_field(self.wl_frame)
        self.entry_wordlist.bind("<KeyRelease>", lambda e: self._on_change())

        f, self.entry_iprange = make_row(
            grid, "IP Range:", lambda p: make_entry(p, "192.168.1.1-254"))
        grid.add_field(f)
        self.entry_iprange.bind("<KeyRelease>", lambda e: self._on_change())

        f, self.entry_ip = make_row(
            grid, "Single IP:", lambda p: make_entry(p, "192.168.1.5"))
        grid.add_field(f)
        self.entry_ip.bind("<KeyRelease>", lambda e: self._on_change())

        f, self.entry_singleurl = make_row(
            grid, "Single URL:", lambda p: make_entry(p, "http://192.168.1.5:8080/admin"))
        grid.add_field(f)
        self.entry_singleurl.bind("<KeyRelease>", lambda e: self._on_change())

        f, self.entry_ports = make_row(
            grid, "Ports:", lambda p: make_entry(p, "80,443,8080"))
        grid.add_field(f)
        self.entry_ports.bind("<KeyRelease>", lambda e: self._on_change())

        f, self.entry_path = make_row(
            grid, "Append Path:", lambda p: make_entry(p, "/admin"))
        grid.add_field(f)
        self.entry_path.bind("<KeyRelease>", lambda e: self._on_change())

        f, self.combo_encode = make_row(grid, "URL Encoding:", lambda p: make_combo(
            p, ["none", "single", "double"], 0))
        grid.add_field(f)
        self.combo_encode.bind("<<ComboboxSelected>>", lambda e: self._on_change())

        grid.relayout()

        # ---- ADVANCED ----
        sec = Section(parent, "ADVANCED")
        sec.pack(**pad)
        grid = ResponsiveFrame(sec, cols_wide=2)
        grid.pack(fill="x")

        f, self.entry_timeout = make_row(
            grid, "Timeout (sec):", lambda p: make_entry(p, width=8))
        self.entry_timeout.insert(0, "5")
        grid.add_field(f)
        self.entry_timeout.bind("<KeyRelease>", lambda e: self._on_change())

        f, self.entry_threads = make_row(
            grid, "Threads:", lambda p: make_entry(p, width=8))
        self.entry_threads.insert(0, "1")
        grid.add_field(f)
        self.entry_threads.bind("<KeyRelease>", lambda e: self._on_change())

        f, self.entry_threshold = make_row(
            grid, "Confidence Threshold:", lambda p: make_entry(p, width=8))
        self.entry_threshold.insert(0, "70")
        grid.add_field(f)
        self.entry_threshold.bind("<KeyRelease>", lambda e: self._on_change())

        f, self.entry_proxy = make_row(
            grid, "Proxy:", lambda p: make_entry(p, "http://127.0.0.1:8080"))
        grid.add_field(f)
        self.entry_proxy.bind("<KeyRelease>", lambda e: self._on_change())

        grid.relayout()

        # ---- OUTPUT OPTIONS ----
        sec = Section(parent, "OUTPUT")
        sec.pack(**pad)
        grid = ResponsiveFrame(sec, cols_wide=2)
        grid.pack(fill="x")

        f, self.combo_format = make_row(grid, "Format:", lambda p: make_combo(
            p, ["text", "json", "xml"], 0))
        grid.add_field(f)
        self.combo_format.bind("<<ComboboxSelected>>", lambda e: self._on_change())

        f, self.entry_outfile = make_row(
            grid, "Output File:", lambda p: make_entry(p, "/path/to/output.txt"))
        grid.add_field(f)
        self.entry_outfile.bind("<KeyRelease>", lambda e: self._on_change())

        # Checkboxes in their own row
        chk_frame = tk.Frame(sec, bg=BG)
        chk_frame.pack(fill="x", padx=4, pady=2)
        self.chk_verbose, self.var_verbose = make_check(chk_frame, "Verbose (-v)")
        self.chk_verbose.pack(side="left", padx=(0, 16))
        self.chk_quiet, self.var_quiet = make_check(chk_frame, "Quiet (-q)")
        self.chk_quiet.pack(side="left", padx=(0, 16))
        self.chk_showresp, self.var_showresp = make_check(chk_frame, "Show Response (-s)")
        self.chk_showresp.pack(side="left")

        self.var_verbose.trace_add("write", lambda *a: self._on_change())
        self.var_quiet.trace_add("write", lambda *a: self._on_change())
        self.var_showresp.trace_add("write", lambda *a: self._on_change())

        grid.relayout()

        # ---- COMMAND PREVIEW ----
        sec = Section(parent, "COMMAND")
        sec.pack(**pad)

        self.cmd_label = tk.Label(sec, text="", font=FONT_SM, fg=FG_ACCENT, bg=BG_INPUT,
                                  anchor="w", relief="solid", bd=1, padx=6, pady=4,
                                  wraplength=1000, justify="left")
        self.cmd_label.pack(fill="x", pady=(0, 6))

        btn_bar = tk.Frame(sec, bg=BG)
        btn_bar.pack(fill="x")

        self.btn_run = tk.Button(btn_bar, text="[  RUN SCAN  ]", font=FONT,
                                 bg=BG2, fg=FG, relief="solid", bd=1,
                                 activebackground="#333", activeforeground=FG,
                                 highlightthickness=0, command=self._run_scan)
        self.btn_run.pack(side="left", padx=(0, 6))

        tk.Button(btn_bar, text="[ COPY CMD ]", font=FONT_SM, bg=BG2, fg=FG,
                  relief="solid", bd=1, highlightthickness=0, activebackground="#333",
                  activeforeground=FG, command=self._copy_cmd).pack(side="left", padx=(0, 6))

        tk.Button(btn_bar, text="[ STOP ]", font=FONT_SM, bg=BG2, fg="#cc6666",
                  relief="solid", bd=1, highlightthickness=0, activebackground="#333",
                  activeforeground="#cc6666", command=self._stop_scan).pack(side="left", padx=(0, 6))

        tk.Button(btn_bar, text="[ RESET ]", font=FONT_SM, bg=BG2, fg=FG,
                  relief="solid", bd=1, highlightthickness=0, activebackground="#333",
                  activeforeground=FG, command=self._reset).pack(side="left")

    # ----------------------------------------------------------------
    # Editor + Output (bottom half)
    # ----------------------------------------------------------------

    def _build_editor(self, parent):
        # Notebook with two tabs: Request Editor, Output
        nb_frame = tk.Frame(parent, bg=BG)
        nb_frame.pack(fill="both", expand=True)

        # Tab buttons
        tab_bar = tk.Frame(nb_frame, bg=BG2)
        tab_bar.pack(fill="x")

        self._tab_btns = {}
        self._tab_frames = {}

        for name in ["REQUEST EDITOR", "OUTPUT"]:
            btn = tk.Button(tab_bar, text=f"  {name}  ", font=FONT_SM, bg=BG2, fg=FG_DIM,
                            relief="flat", bd=0, highlightthickness=0,
                            activebackground=BG, activeforeground=FG,
                            command=lambda n=name: self._switch_tab(n))
            btn.pack(side="left", padx=1)
            self._tab_btns[name] = btn

        # --- Request Editor tab ---
        editor_frame = tk.Frame(nb_frame, bg=BG)
        self._tab_frames["REQUEST EDITOR"] = editor_frame

        # Toolbar
        toolbar = tk.Frame(editor_frame, bg=BG2, pady=4, padx=8)
        toolbar.pack(fill="x")

        tk.Label(toolbar, text="Marker:", font=FONT_SM, fg=FG_DIM, bg=BG2).pack(side="left")

        self.combo_marker = ttk.Combobox(toolbar, values=MARKERS, state="readonly",
                                         width=8, font=FONT_SM)
        self.combo_marker.current(0)
        self.combo_marker.pack(side="left", padx=4)

        tk.Button(toolbar, text="[ INSERT ]", font=FONT_SM, bg=BG2, fg=FG,
                  relief="solid", bd=1, highlightthickness=0, activebackground="#333",
                  activeforeground=FG, command=self._insert_marker).pack(side="left", padx=(0, 8))

        tk.Button(toolbar, text="[ CLEAR ]", font=FONT_SM, bg=BG2, fg=FG,
                  relief="solid", bd=1, highlightthickness=0, activebackground="#333",
                  activeforeground=FG, command=self._clear_editor).pack(side="left")

        self.cursor_label = tk.Label(toolbar, text="Ln 1, Col 1", font=FONT_SM,
                                     fg=FG_DIM, bg=BG2)
        self.cursor_label.pack(side="right")

        # Text area
        self.text_request = scrolledtext.ScrolledText(
            editor_frame, font=FONT_SM, bg=BG_INPUT, fg=FG,
            insertbackground=FG, relief="flat", bd=0,
            highlightthickness=0, wrap="none", undo=True,
            selectbackground="#506050", selectforeground=FG,
        )
        self.text_request.pack(fill="both", expand=True)
        self.text_request.insert("1.0",
            "# Paste your raw HTTP request here\n"
            "# Example:\n"
            "#\n"
            "# GET /api/fetch?url=SSRF HTTP/1.1\n"
            "# Host: target.example.com\n"
            "# Authorization: Bearer token123\n"
            "# Content-Type: application/json\n"
        )
        self.text_request.bind("<KeyRelease>", self._update_cursor)
        self.text_request.bind("<ButtonRelease-1>", self._update_cursor)

        # --- Output tab ---
        output_frame = tk.Frame(nb_frame, bg=BG)
        self._tab_frames["OUTPUT"] = output_frame

        self.text_output = scrolledtext.ScrolledText(
            output_frame, font=FONT_SM, bg="#2e2e2e", fg="#d0d0d0",
            insertbackground=FG, relief="flat", bd=0,
            highlightthickness=0, wrap="word", state="disabled",
            selectbackground="#505050", selectforeground=FG,
        )
        self.text_output.pack(fill="both", expand=True)

        # Show editor by default
        self._switch_tab("REQUEST EDITOR")

    def _switch_tab(self, name):
        for n, frame in self._tab_frames.items():
            frame.pack_forget()
        self._tab_frames[name].pack(fill="both", expand=True)
        for n, btn in self._tab_btns.items():
            if n == name:
                btn.configure(bg=BG, fg=FG)
            else:
                btn.configure(bg=BG2, fg=FG_DIM)

    # ----------------------------------------------------------------
    # Status Bar
    # ----------------------------------------------------------------

    def _build_statusbar(self):
        bar = tk.Frame(self.root, bg=BG2, pady=2)
        bar.pack(fill="x", side="bottom")
        self.status_label = tk.Label(bar, text="[*] Ready", font=FONT_SM,
                                     fg=FG_DIM, bg=BG2, anchor="w", padx=8)
        self.status_label.pack(side="left")
        tk.Label(bar, text=f"{TOOL_NAME} v{VERSION}", font=FONT_SM,
                 fg=FG_DIM, bg=BG2, anchor="e", padx=8).pack(side="right")

    def _set_status(self, text):
        self.status_label.configure(text=text)

    # ----------------------------------------------------------------
    # Logic: Visibility & Command
    # ----------------------------------------------------------------

    def _get_mode(self):
        return "inspect" if "Inspection" in self.combo_mode.get() else "inject"

    def _get_ml(self):
        return "Yes" in self.combo_ml.get()

    def _get_source(self):
        val = self.combo_source.get()
        if "File" in val:
            return "file"
        elif "URL" in val:
            return "url"
        return "editor"

    def _get_strategy(self):
        val = self.combo_strategy.get()
        if "custom" in val:
            return "custom"
        return val

    def _on_change(self):
        mode = self._get_mode()
        ml = self._get_ml()
        source = self._get_source()
        strategy = self._get_strategy()

        # Param visibility
        if mode == "inspect":
            self.entry_param.configure(state="disabled")
        else:
            self.entry_param.configure(state="normal")

        # Source visibility
        self.entry_file.configure(state="normal" if source == "file" else "disabled")
        self.entry_url.configure(state="normal" if source == "url" else "disabled")

        # Payloads section
        if mode == "inspect":
            for child in self.sec_payloads.winfo_children():
                self._set_children_state(child, "disabled")
        else:
            for child in self.sec_payloads.winfo_children():
                self._set_children_state(child, "normal")

        # Wordlist
        self.entry_wordlist.configure(state="normal" if strategy == "custom" else "disabled")

        # ML-dependent fields
        if not ml:
            self.entry_threads.configure(state="disabled")
            self.entry_threshold.configure(state="disabled")

        # Verbose/quiet mutual exclusion
        if self.var_verbose.get() and self.var_quiet.get():
            self.var_quiet.set(False)

        self._update_command()

    def _set_children_state(self, widget, state):
        try:
            widget.configure(state=state)
        except Exception:
            pass
        for child in widget.winfo_children():
            self._set_children_state(child, state)

    def _update_command(self):
        ml = self._get_ml()
        mode = self._get_mode()
        source = self._get_source()
        strategy = self._get_strategy()

        script = "python3 neuralforger-main.py" if ml else "python3 main.py"
        parts = [script]

        # Source
        if source == "file" and self.entry_file.get().strip():
            parts.append(f'-r "{self.entry_file.get().strip()}"')
        elif source == "url" and self.entry_url.get().strip():
            parts.append(f'-u "{self.entry_url.get().strip()}"')
        elif source == "editor":
            parts.append("-r <request_from_editor>")

        # Mode
        if mode == "inspect" and ml:
            parts.append("-i")
        elif self.entry_param.get().strip():
            parts.append(f"-p {self.entry_param.get().strip()}")

        # Payloads
        if mode == "inject":
            if ml and strategy != "ml-recommended":
                parts.append(f"--payload-strategy {strategy}")
            if strategy == "custom" and self.entry_wordlist.get().strip():
                parts.append(f'-w "{self.entry_wordlist.get().strip()}"')
            if self.entry_iprange.get().strip():
                parts.append(f"--ip-range {self.entry_iprange.get().strip()}")
            if self.entry_ip.get().strip():
                parts.append(f"--ip {self.entry_ip.get().strip()}")
            if self.entry_singleurl.get().strip():
                parts.append(f'--single-url "{self.entry_singleurl.get().strip()}"')
            if self.entry_ports.get().strip():
                parts.append(f"-P {self.entry_ports.get().strip()}")
            if self.entry_path.get().strip():
                parts.append(f"--path {self.entry_path.get().strip()}")
            enc = self.combo_encode.get()
            if enc != "none":
                parts.append(f"--encode {enc}")

        # Advanced
        t = self.entry_timeout.get().strip()
        if t and t != "5":
            parts.append(f"-t {t}")
        if ml:
            th = self.entry_threads.get().strip()
            if th and th != "1":
                parts.append(f"--threads {th}")
            ct = self.entry_threshold.get().strip()
            if ct and ct != "70":
                parts.append(f"--confidence-threshold {ct}")
        if self.entry_proxy.get().strip():
            parts.append(f'--proxy "{self.entry_proxy.get().strip()}"')

        # Output
        fmt = self.combo_format.get()
        if fmt != "text":
            parts.append(f"--format {fmt}")
        if self.entry_outfile.get().strip():
            parts.append(f'-o "{self.entry_outfile.get().strip()}"')
        if self.var_verbose.get():
            parts.append("-v")
        if self.var_quiet.get():
            parts.append("-q")
        if self.var_showresp.get():
            parts.append("-s")

        cmd = " ".join(parts)
        self.cmd_label.configure(text=cmd)
        self._cmd_text = cmd

    def _schedule_update(self):
        self._on_change()

    # ----------------------------------------------------------------
    # Actions
    # ----------------------------------------------------------------

    def _browse_file(self):
        path = filedialog.askopenfilename(
            title="Select Request File",
            filetypes=[("Text files", "*.txt"), ("All files", "*.*")]
        )
        if path:
            self.entry_file.delete(0, "end")
            self.entry_file.insert(0, path)
            self._on_change()

    def _insert_marker(self):
        marker = self.combo_marker.get()
        try:
            self.text_request.insert("insert", marker)
            self._set_status(f'[+] Marker "{marker}" inserted')
        except Exception:
            pass

    def _clear_editor(self):
        self.text_request.delete("1.0", "end")
        self._set_status("[*] Editor cleared")

    def _update_cursor(self, event=None):
        pos = self.text_request.index("insert")
        line, col = pos.split(".")
        self.cursor_label.configure(text=f"Ln {line}, Col {int(col)+1}")

    def _copy_cmd(self):
        cmd = getattr(self, "_cmd_text", "")
        if cmd:
            self.root.clipboard_clear()
            self.root.clipboard_append(cmd)
            self._set_status("[+] Command copied to clipboard")

    def _reset(self):
        self.combo_mode.current(0)
        self.combo_ml.current(0)
        self.entry_param.delete(0, "end")
        self.combo_source.current(0)
        self.entry_file.delete(0, "end")
        self.entry_url.delete(0, "end")
        self.combo_strategy.current(0)
        self.entry_wordlist.delete(0, "end")
        self.entry_iprange.delete(0, "end")
        self.entry_ip.delete(0, "end")
        self.entry_singleurl.delete(0, "end")
        self.entry_ports.delete(0, "end")
        self.entry_path.delete(0, "end")
        self.combo_encode.current(0)
        self.entry_timeout.delete(0, "end")
        self.entry_timeout.insert(0, "5")
        self.entry_threads.delete(0, "end")
        self.entry_threads.insert(0, "1")
        self.entry_threshold.delete(0, "end")
        self.entry_threshold.insert(0, "70")
        self.entry_proxy.delete(0, "end")
        self.combo_format.current(0)
        self.entry_outfile.delete(0, "end")
        self.var_verbose.set(False)
        self.var_quiet.set(False)
        self.var_showresp.set(False)
        self._on_change()
        self._set_status("[*] All options reset")

    # ----------------------------------------------------------------
    # Run Scan (real execution)
    # ----------------------------------------------------------------

    def _run_scan(self):
        if self.process and self.process.poll() is None:
            self._set_status("[-] Scan already running. Stop it first.")
            return

        mode = self._get_mode()
        source = self._get_source()
        ml = self._get_ml()

        # Validation
        errors = []
        if mode == "inject" and not self.entry_param.get().strip():
            errors.append("Target parameter is required for injection mode.")
        if source == "file" and not self.entry_file.get().strip():
            errors.append("No request file path specified.")
        if source == "url" and not self.entry_url.get().strip():
            errors.append("No target URL specified.")
        if source == "editor":
            content = self.text_request.get("1.0", "end").strip()
            lines = [l for l in content.split("\n") if l.strip() and not l.strip().startswith("#")]
            if not lines:
                errors.append("Request editor is empty.")
            else:
                has_marker = any(m in content for m in MARKERS)
                if not has_marker:
                    errors.append("No injection marker found. Insert SSRF, ***, INJECT, or FUZZ.")

        if errors:
            self._set_status(f"[-] {errors[0]}")
            self._append_output("[!] Validation errors:\n" + "\n".join(f"  - {e}" for e in errors) + "\n")
            self._switch_tab("OUTPUT")
            return

        # Build the actual command
        script = "neuralforger-main.py" if ml else "main.py"
        script_path = os.path.join(BASE_DIR, script)

        cmd_parts = [sys.executable, script_path]

        # Handle editor source: save to temp file
        self._temp_file = None
        if source == "editor":
            content = self.text_request.get("1.0", "end").strip()
            lines = [l for l in content.split("\n") if not l.strip().startswith("#")]
            clean = "\n".join(lines)
            fd, tmp_path = tempfile.mkstemp(suffix=".txt", prefix="nf_request_")
            with os.fdopen(fd, "w") as f:
                f.write(clean)
            self._temp_file = tmp_path
            cmd_parts.extend(["-r", tmp_path])
        elif source == "file":
            cmd_parts.extend(["-r", self.entry_file.get().strip()])
        elif source == "url":
            cmd_parts.extend(["-u", self.entry_url.get().strip()])

        # Mode
        if mode == "inspect" and ml:
            cmd_parts.append("-i")
        elif self.entry_param.get().strip():
            cmd_parts.extend(["-p", self.entry_param.get().strip()])

        # Payloads
        if mode == "inject":
            strategy = self._get_strategy()
            if ml and strategy != "ml-recommended":
                cmd_parts.extend(["--payload-strategy", strategy])
            if strategy == "custom" and self.entry_wordlist.get().strip():
                cmd_parts.extend(["-w", self.entry_wordlist.get().strip()])
            if self.entry_iprange.get().strip():
                cmd_parts.extend(["--ip-range", self.entry_iprange.get().strip()])
            if self.entry_ip.get().strip():
                cmd_parts.extend(["--ip", self.entry_ip.get().strip()])
            if self.entry_singleurl.get().strip():
                cmd_parts.extend(["--single-url", self.entry_singleurl.get().strip()])
            if self.entry_ports.get().strip():
                cmd_parts.extend(["-P", self.entry_ports.get().strip()])
            if self.entry_path.get().strip():
                cmd_parts.extend(["--path", self.entry_path.get().strip()])
            enc = self.combo_encode.get()
            if enc != "none":
                cmd_parts.extend(["--encode", enc])

        # Advanced
        t = self.entry_timeout.get().strip()
        if t and t != "5":
            cmd_parts.extend(["-t", t])
        if ml:
            th = self.entry_threads.get().strip()
            if th and th != "1":
                cmd_parts.extend(["--threads", th])
            ct = self.entry_threshold.get().strip()
            if ct and ct != "70":
                cmd_parts.extend(["--confidence-threshold", ct])
        if self.entry_proxy.get().strip():
            cmd_parts.extend(["--proxy", self.entry_proxy.get().strip()])

        # Output
        fmt = self.combo_format.get()
        if fmt != "text":
            cmd_parts.extend(["--format", fmt])
        if self.entry_outfile.get().strip():
            cmd_parts.extend(["-o", self.entry_outfile.get().strip()])
        if self.var_verbose.get():
            cmd_parts.append("-v")
        if self.var_quiet.get():
            cmd_parts.append("-q")
        if self.var_showresp.get():
            cmd_parts.append("-s")

        # Switch to output tab and run
        self._switch_tab("OUTPUT")
        self._clear_output()
        self._append_output(f"[*] Executing: {' '.join(cmd_parts)}\n")
        self._append_output("=" * 60 + "\n\n")
        self._set_status("[*] Scan running...")
        self.btn_run.configure(state="disabled")

        # Run in thread
        thread = threading.Thread(target=self._execute, args=(cmd_parts,), daemon=True)
        thread.start()

    def _execute(self, cmd_parts):
        try:
            self.process = subprocess.Popen(
                cmd_parts,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                cwd=BASE_DIR,
                text=True,
                bufsize=1,
            )

            for line in iter(self.process.stdout.readline, ""):
                self.root.after(0, self._append_output, line)

            self.process.wait()
            rc = self.process.returncode
            self.root.after(0, self._append_output,
                            f"\n{'=' * 60}\n[*] Process exited with code {rc}\n")
            self.root.after(0, self._set_status,
                            f"[+] Scan finished (exit code {rc})")
        except Exception as e:
            self.root.after(0, self._append_output, f"\n[!] Error: {e}\n")
            self.root.after(0, self._set_status, f"[-] Error: {e}")
        finally:
            self.process = None
            self.root.after(0, lambda: self.btn_run.configure(state="normal"))
            # Cleanup temp file
            tmp = getattr(self, "_temp_file", None)
            if tmp and os.path.exists(tmp):
                try:
                    os.unlink(tmp)
                except Exception:
                    pass

    def _stop_scan(self):
        if self.process and self.process.poll() is None:
            try:
                self.process.send_signal(signal.SIGINT)
                self._set_status("[!] Scan interrupted (SIGINT sent)")
                self._append_output("\n[!] Scan interrupted by user\n")
            except Exception:
                self.process.kill()
                self._set_status("[!] Scan killed")
        else:
            self._set_status("[*] No scan running")

    def _append_output(self, text):
        self.text_output.configure(state="normal")
        self.text_output.insert("end", text)
        self.text_output.see("end")
        self.text_output.configure(state="disabled")

    def _clear_output(self):
        self.text_output.configure(state="normal")
        self.text_output.delete("1.0", "end")
        self.text_output.configure(state="disabled")


# ============================================================================
# Entry point
# ============================================================================

def main():
    root = tk.Tk()
    app = NeuralForgerGUI(root)
    root.mainloop()


if __name__ == "__main__":
    main()