"""Password Generator - a desktop program with a window (tkinter).

Tabs:
    Generator   - random password (length and character types of your choice)
    Passphrase  - password made of random words
    Check       - strength of any password, updated while you type
    Saved       - passwords saved to a file

Only the standard library is used, nothing to install.
"""
import math
import os
import secrets
import string
import sys
import tkinter as tk
from datetime import datetime
from tkinter import messagebox, simpledialog, ttk

# ---------- settings ----------
if getattr(sys, "frozen", False):                  # running as a ready .exe made by PyInstaller
    APP_DIR = os.path.dirname(sys.executable)
else:
    APP_DIR = os.path.dirname(os.path.abspath(__file__))
SAVE_FILE = os.path.join(APP_DIR, "saved_passwords.txt")
GUESSES_PER_SECOND = 10_000_000_000      # assumption: a very fast attacker
SYMBOLS = "!@#$%^&*()-_=+[]{};:,.?"
SIMILAR = "O0Il1|"                       # characters that look alike

COMMON = {
    "123456", "password", "12345678", "qwerty", "123456789", "12345", "1234",
    "111111", "1234567", "dragon", "123123", "baseball", "abc123", "football",
    "monkey", "letmein", "shadow", "master", "666666", "qwertyuiop", "123321",
    "mustang", "1234567890", "superman", "1qaz2wsx", "121212", "000000",
    "qazwsx", "123qwe", "trustno1", "zxcvbnm", "asdfgh", "sunshine", "iloveyou",
    "princess", "admin", "welcome", "login", "password1", "qwerty123", "passw0rd",
}

WORDS = sorted(set("""
acorn amber anchor apple arrow aspen atlas badge baker bamboo banjo basil beach
beacon berry bison blanket bloom bridge bronze brook bubble cabin cactus camel
candle canyon carpet castle cedar cherry cinder circle clover cobalt comet copper
coral cotton crane crystal curtain daisy dawn desert diamond dolphin dragon drift
dune eagle echo ember engine falcon feather fern fiddle field flame flint forest
fossil frost galaxy garden garlic ginger glacier gold granite grape gravel harbor
harvest hazel heron honey horizon iceberg island ivory jacket jaguar jasmine jewel
jungle kernel kettle kite koala ladder lagoon lantern lava lemon lilac lizard lotus
lunar magnet mango maple marble marsh meadow melon mirror mist monkey moss mountain
nectar needle nickel noodle nutmeg oasis ocean olive onyx opal orange orchid otter
oyster paddle panda parrot peach pearl pebble pepper pigeon pillow pine planet plum
pocket prairie pumpkin puzzle quartz quest quill rabbit ranger raven reef ribbon
river robin rocket saddle saffron sailor salmon sand shadow silver sketch spark
sparrow spider spruce squirrel star stone storm sugar summit sunset swan thistle
thunder tiger timber tulip tunnel turtle umbrella valley velvet vessel violin
wagon walnut whale willow window winter wolf yarn yellow zebra zephyr zinc
""".split()))


# ====================== logic (no windows here) ======================
def generate_password(length, use_upper, use_digits, use_symbols, avoid_similar):
    """Random password. Uses `secrets` (safe for passwords), not `random`."""
    groups = [string.ascii_lowercase]
    if use_upper:
        groups.append(string.ascii_uppercase)
    if use_digits:
        groups.append(string.digits)
    if use_symbols:
        groups.append(SYMBOLS)
    if avoid_similar:
        groups = ["".join(c for c in g if c not in SIMILAR) for g in groups]
    pool = "".join(groups)

    chars = [secrets.choice(g) for g in groups]                       # one from each group
    chars += [secrets.choice(pool) for _ in range(length - len(chars))]
    secrets.SystemRandom().shuffle(chars)                             # mix the order
    return "".join(chars)


def generate_passphrase(count, capitalize, add_number):
    words = [secrets.choice(WORDS) for _ in range(count)]
    if capitalize:
        words = [w.capitalize() for w in words]
    phrase = "-".join(words)
    bits = count * math.log2(len(WORDS))
    if add_number:
        phrase += "-" + f"{secrets.randbelow(100):02d}"
        bits += math.log2(100)
    return phrase, bits


def analyze(password):
    """Returns (entropy in bits, list of tips). Entropy H = L * log2(N)."""
    has_lower = any(c in string.ascii_lowercase for c in password)
    has_upper = any(c in string.ascii_uppercase for c in password)
    has_digit = any(c in string.digits for c in password)
    has_other = any(c not in string.ascii_letters + string.digits for c in password)
    pool = 26 * has_lower + 26 * has_upper + 10 * has_digit + 33 * has_other
    entropy = len(password) * math.log2(pool) if pool else 0.0

    tips = []
    if password.lower() in COMMON:
        entropy = min(entropy, 10.0)
        tips.append("This password is in the list of very common passwords!")
    if len(set(password)) < len(password) / 2:
        entropy *= 0.7
        tips.append("Many repeated characters make it easier to guess.")
    if len(password) < 12:
        tips.append("Use at least 12 characters.")
    if not has_upper:
        tips.append("Add uppercase letters.")
    if not has_digit:
        tips.append("Add digits.")
    if not has_other:
        tips.append("Add symbols like ! @ # $.")
    return entropy, tips


def rating(entropy):
    levels = [(28, "Very weak"), (40, "Weak"), (60, "Medium"), (80, "Strong")]
    for limit, label in levels:
        if entropy < limit:
            return label
    return "Very strong"


def crack_time(entropy):
    """Average time to guess by brute force: half of all variants."""
    seconds = 2 ** entropy / 2 / GUESSES_PER_SECOND
    minute, hour, day, year = 60, 3600, 86400, 86400 * 365
    if seconds < 1:
        return "less than a second"
    if seconds < minute:
        return f"{seconds:.0f} seconds"
    if seconds < hour:
        return f"{seconds / minute:.0f} minutes"
    if seconds < day:
        return f"{seconds / hour:.0f} hours"
    if seconds < year:
        return f"{seconds / day:.0f} days"
    years = seconds / year
    if years < 1000:
        return f"{years:,.0f} years"
    if years < 1e6:
        return f"{years / 1e3:,.0f} thousand years"
    if years < 1e9:
        return f"{years / 1e6:,.0f} million years"
    if years < 1e12:
        return f"{years / 1e9:,.0f} billion years"
    return "trillions of years"


def read_saved():
    if not os.path.exists(SAVE_FILE):
        return []
    with open(SAVE_FILE, encoding="utf-8") as f:
        return [line for line in f.read().splitlines() if line.strip()]


def write_saved(lines):
    with open(SAVE_FILE, "w", encoding="utf-8") as f:
        for line in lines:
            f.write(line + "\n")


def save_password(label, value):
    label = label.replace("|", "/").replace("\n", " ")          # keep the file format simple
    with open(SAVE_FILE, "a", encoding="utf-8") as f:
        f.write(f"{datetime.now():%Y-%m-%d %H:%M} | {label} | {value}\n")


# ====================== design (dark "tech" style) ======================
BG, PANEL, PANEL2, FIELD = "#080c12", "#0e141d", "#151e2b", "#05080d"
BORDER = "#1f2f45"
TEXT, MUTED = "#d5e2f3", "#6b819f"
NEON, GREEN, AMBER, RED = "#00e5ff", "#39ff88", "#ffb454", "#ff4d6d"
SELECT = "#0e3a4d"
LEVEL_COLORS = {"Very weak": RED, "Weak": "#ff8a3d", "Medium": "#ffd23f",
                "Strong": GREEN, "Very strong": NEON}
MONO = "Consolas"
BAR_WIDTH = 632
BAR_SEGMENTS = 32


def field_options(size=13):
    """Look of text fields: dark box, green text, neon frame when active."""
    return dict(font=(MONO, size), relief="flat", bg=FIELD, fg=GREEN, insertbackground=NEON,
                highlightthickness=1, highlightbackground=BORDER, highlightcolor=NEON,
                selectbackground=SELECT, selectforeground=NEON)


class StrengthView(ttk.Frame):
    """Segmented strength bar, level name, entropy, crack time and tips."""

    def __init__(self, parent):
        super().__init__(parent)
        top = ttk.Frame(self)
        top.pack(fill="x")
        ttk.Label(top, text="STRENGTH", style="Caption.TLabel").pack(side="left")
        self.level = ttk.Label(top, text="", style="Level.TLabel")
        self.level.pack(side="right")
        self.canvas = tk.Canvas(self, width=BAR_WIDTH, height=14, bg=PANEL, highlightthickness=0)
        self.canvas.pack(pady=(6, 10))
        self.info = ttk.Label(self, text="", style="Info.TLabel", justify="left")
        self.info.pack(anchor="w")
        self.tips = ttk.Label(self, text="", style="Tip.TLabel", wraplength=BAR_WIDTH, justify="left")
        self.tips.pack(anchor="w", pady=(8, 0))
        self.clear()

    def _draw(self, filled, color):
        self.canvas.delete("all")
        gap = 3
        width = (BAR_WIDTH - gap * (BAR_SEGMENTS - 1)) / BAR_SEGMENTS
        for i in range(BAR_SEGMENTS):
            x = i * (width + gap)
            self.canvas.create_rectangle(x, 0, x + width, 14, outline="",
                                         fill=color if i < filled else "#1a2638")

    def clear(self):
        self._draw(0, "#1a2638")
        self.level.config(text="")
        self.info.config(text="")
        self.tips.config(text="")

    def show(self, entropy, tips, extra=""):
        label = rating(entropy)
        color = LEVEL_COLORS[label]
        self._draw(max(1, round(min(entropy, 100) / 100 * BAR_SEGMENTS)), color)
        self.level.config(text=label.upper(), foreground=color)
        text = f"entropy: {entropy:.1f} bits  //  crack time: {crack_time(entropy)}"
        if extra:
            text += "\n" + extra
        self.info.config(text=text)
        self.tips.config(text="\n".join("[!] " + t for t in tips))


class OutputBox(ttk.Frame):
    """Terminal-like result field with Copy and Save buttons."""

    def __init__(self, parent, app):
        super().__init__(parent)
        self.app = app
        ttk.Label(self, text="OUTPUT", style="Caption.TLabel").pack(anchor="w", pady=(0, 6))
        self.text = tk.Text(self, height=2, width=40, wrap="char", font=(MONO, 15, "bold"),
                            relief="flat", bg=FIELD, fg=GREEN, padx=14, pady=14, state="disabled",
                            highlightthickness=1, highlightbackground="#134e5a", cursor="arrow",
                            selectbackground=SELECT)
        self.text.tag_configure("prompt", foreground=NEON)
        self.text.tag_configure("value", foreground=GREEN)
        self.text.pack(fill="x")
        buttons = ttk.Frame(self)
        buttons.pack(fill="x", pady=(10, 0))
        ttk.Button(buttons, text="COPY", command=self.copy).pack(side="left", padx=(0, 8))
        ttk.Button(buttons, text="SAVE TO FILE", command=self.save).pack(side="left")
        self.status = ttk.Label(buttons, text="", style="Ok.TLabel")
        self.status.pack(side="left", padx=12)
        self.value = ""

    def set(self, value):
        self.value = value
        self.text.config(state="normal")
        self.text.delete("1.0", "end")
        self.text.insert("end", "> ", "prompt")
        self.text.insert("end", value, "value")
        self.text.config(state="disabled")
        self.status.config(text="")

    def _message(self, text):
        self.status.config(text=text)
        self.after(2000, lambda: self.status.config(text=""))

    def copy(self):
        if not self.value:
            return
        self.app.clipboard_clear()
        self.app.clipboard_append(self.value)
        self._message("COPIED")

    def save(self):
        if not self.value:
            return
        name = simpledialog.askstring("Save password", "Name for this password (for example: email):",
                                      parent=self.app)
        if name is None:
            return
        save_password(name.strip() or "no name", self.value)
        self.app.refresh_saved()
        self._message("SAVED")


class GeneratorTab(ttk.Frame):
    def __init__(self, parent, app):
        super().__init__(parent, padding=20)
        self.length = tk.IntVar(value=16)
        self.upper = tk.BooleanVar(value=True)
        self.digits = tk.BooleanVar(value=True)
        self.symbols = tk.BooleanVar(value=True)
        self.similar = tk.BooleanVar(value=False)

        row = ttk.Frame(self)
        row.pack(fill="x")
        ttk.Label(row, text="LENGTH", style="Caption.TLabel").pack(side="left")
        self.length_label = ttk.Label(row, text="16", style="Value.TLabel")
        self.length_label.pack(side="right")
        scale = ttk.Scale(self, from_=8, to=64, orient="horizontal", command=self._on_scale)
        scale.set(16)
        scale.pack(fill="x", pady=(6, 14))

        checks = ttk.Frame(self)
        checks.pack(fill="x")
        options = [("Uppercase letters (A-Z)", self.upper), ("Digits (0-9)", self.digits),
                   ("Symbols (! @ # $)", self.symbols), ("Avoid similar (O 0 l 1 I)", self.similar)]
        for i, (text, var) in enumerate(options):
            ttk.Checkbutton(checks, text=text, variable=var).grid(row=i // 2, column=i % 2,
                                                                   sticky="w", padx=(0, 40), pady=3)

        ttk.Button(self, text="GENERATE PASSWORD", style="Accent.TButton",
                   command=self.generate).pack(fill="x", pady=18)
        self.output = OutputBox(self, app)
        self.output.pack(fill="x")
        self.strength = StrengthView(self)
        self.strength.pack(fill="x", pady=(18, 0))
        self.generate()

    def _on_scale(self, value):
        n = int(float(value))
        self.length.set(n)
        self.length_label.config(text=str(n))

    def generate(self):
        password = generate_password(self.length.get(), self.upper.get(), self.digits.get(),
                                     self.symbols.get(), self.similar.get())
        entropy, tips = analyze(password)
        self.output.set(password)
        self.strength.show(entropy, tips)


class PassphraseTab(ttk.Frame):
    def __init__(self, parent, app):
        super().__init__(parent, padding=20)
        self.count = tk.IntVar(value=8)
        self.capitalize = tk.BooleanVar(value=True)
        self.number = tk.BooleanVar(value=True)

        row = ttk.Frame(self)
        row.pack(fill="x")
        ttk.Label(row, text="NUMBER OF WORDS", style="Caption.TLabel").pack(side="left")
        ttk.Spinbox(row, from_=3, to=10, width=5, textvariable=self.count,
                    command=self.generate).pack(side="left", padx=14)
        ttk.Checkbutton(self, text="Capitalize each word", variable=self.capitalize).pack(anchor="w", pady=(14, 3))
        ttk.Checkbutton(self, text="Add a number at the end", variable=self.number).pack(anchor="w", pady=3)

        ttk.Button(self, text="GENERATE PASSPHRASE", style="Accent.TButton",
                   command=self.generate).pack(fill="x", pady=18)
        self.output = OutputBox(self, app)
        self.output.pack(fill="x")
        self.strength = StrengthView(self)
        self.strength.pack(fill="x", pady=(18, 0))
        self.generate()

    def generate(self):
        try:
            count = max(3, min(10, int(self.count.get())))
        except (tk.TclError, ValueError):
            count = 8
        phrase, bits = generate_passphrase(count, self.capitalize.get(), self.number.get())
        self.output.set(phrase)
        self.strength.show(bits, [], f"{count} words from a list of {len(WORDS)}")


class CheckTab(ttk.Frame):
    def __init__(self, parent, app):
        super().__init__(parent, padding=20)
        self.app = app
        ttk.Label(self, text="PASSWORD INPUT", style="Caption.TLabel").pack(anchor="w")
        self.var = tk.StringVar()
        self.entry = tk.Entry(self, textvariable=self.var, show="•", **field_options(14))
        self.entry.pack(fill="x", ipady=9, pady=(6, 10))
        self.show = tk.BooleanVar(value=False)
        ttk.Checkbutton(self, text="Show password", variable=self.show,
                        command=self._toggle).pack(anchor="w")
        actions = ttk.Frame(self)
        actions.pack(fill="x", pady=(12, 0))
        ttk.Button(actions, text="SAVE THIS PASSWORD", command=self.save).pack(side="left")
        self.status = ttk.Label(actions, text="", style="Ok.TLabel")
        self.status.pack(side="left", padx=12)
        self.length = ttk.Label(self, text="", style="Caption.TLabel")
        self.length.pack(anchor="w", pady=(14, 0))
        self.strength = StrengthView(self)
        self.strength.pack(fill="x", pady=(10, 0))
        ttk.Label(self, text="// estimate for random characters. passwords built from\n"
                             "// words or names are easier to guess than the number shows.",
                  style="Caption.TLabel").pack(anchor="w", pady=(22, 0))
        self.var.trace_add("write", lambda *args: self.update_result())

    def _toggle(self):
        self.entry.config(show="" if self.show.get() else "•")

    def _message(self, text, color):
        self.status.config(text=text, foreground=color)
        self.after(2000, lambda: self.status.config(text=""))

    def save(self):
        password = self.var.get()
        if not password:
            self._message("TYPE A PASSWORD FIRST", RED)
            return
        name = simpledialog.askstring("Save password", "Name for this password (for example: email):",
                                      parent=self.app)
        if name is None:
            return
        save_password(name.strip() or "no name", password)
        self.app.refresh_saved()
        self._message("SAVED", GREEN)

    def update_result(self):
        password = self.var.get()
        if not password:
            self.length.config(text="")
            self.strength.clear()
            return
        entropy, tips = analyze(password)
        self.length.config(text=f"LENGTH: {len(password)} CHARACTERS")
        self.strength.show(entropy, tips)


class AddDialog(tk.Toplevel):
    """Small window for adding your own password."""

    def __init__(self, app):
        super().__init__(app)
        self.app = app
        self.title("Add password")
        self.configure(bg=BG)
        self.resizable(False, False)
        self.transient(app)
        self.geometry(f"+{app.winfo_x() + 100}+{app.winfo_y() + 180}")

        body = ttk.Frame(self, padding=22)
        body.pack(fill="both", expand=True, padx=2, pady=2)

        ttk.Label(body, text="NAME  (email, Instagram ...)", style="Caption.TLabel").pack(anchor="w")
        self.name_var = tk.StringVar()
        name_entry = tk.Entry(body, textvariable=self.name_var, width=36, **field_options(12))
        name_entry.pack(fill="x", ipady=7, pady=(6, 14))

        ttk.Label(body, text="PASSWORD", style="Caption.TLabel").pack(anchor="w")
        self.pass_var = tk.StringVar()
        self.pass_entry = tk.Entry(body, textvariable=self.pass_var, show="•", width=36, **field_options(12))
        self.pass_entry.pack(fill="x", ipady=7, pady=(6, 8))
        self.show_var = tk.BooleanVar(value=False)
        ttk.Checkbutton(body, text="Show password", variable=self.show_var,
                        command=self._toggle).pack(anchor="w")

        self.error_label = ttk.Label(body, text="", foreground=RED)
        self.error_label.pack(anchor="w", pady=(10, 0))
        buttons = ttk.Frame(body)
        buttons.pack(fill="x", pady=(8, 0))
        ttk.Button(buttons, text="SAVE", style="Accent.TButton", command=self.save).pack(side="right")
        ttk.Button(buttons, text="CANCEL", command=self.destroy).pack(side="right", padx=8)

        self.bind("<Return>", lambda event: self.save())
        self.bind("<Escape>", lambda event: self.destroy())
        name_entry.focus_set()
        self.grab_set()                      # the main window waits until this one is closed

    def _toggle(self):
        self.pass_entry.config(show="" if self.show_var.get() else "•")

    def save(self):
        password = self.pass_var.get()
        if not password:
            self.error_label.config(text="[!] Please enter a password.")
            return
        save_password(self.name_var.get().strip() or "no name", password)
        self.app.refresh_saved()
        self.destroy()


class SavedTab(ttk.Frame):
    def __init__(self, parent, app):
        super().__init__(parent, padding=20)
        self.app = app
        self.lines = []
        columns = ("date", "name", "password")
        self.tree = ttk.Treeview(self, columns=columns, show="headings", height=14, selectmode="extended")
        for column, title, width in (("date", "DATE", 120), ("name", "NAME", 110), ("password", "PASSWORD", 230)):
            self.tree.heading(column, text=title)
            self.tree.column(column, width=width, anchor="w")
        scroll = ttk.Scrollbar(self, orient="vertical", command=self.tree.yview)
        self.tree.configure(yscrollcommand=scroll.set)
        self.tree.pack(side="left", fill="both", expand=True)
        scroll.pack(side="left", fill="y")

        side = ttk.Frame(self)
        side.pack(side="left", fill="y", padx=(12, 0))
        ttk.Button(side, text="+ ADD", style="Accent.TButton",
                   command=lambda: AddDialog(self.app)).pack(fill="x", pady=(0, 12))
        ttk.Button(side, text="COPY", command=self.copy_selected).pack(fill="x", pady=3)
        ttk.Button(side, text="DELETE", command=self.delete_selected).pack(fill="x", pady=3)
        ttk.Button(side, text="DELETE ALL", command=self.delete_all).pack(fill="x", pady=3)
        ttk.Label(side, text="// plain text file.\n// demo only!", style="Tip.TLabel",
                  justify="left").pack(pady=18)
        self.refresh()

    def refresh(self):
        self.lines = read_saved()
        self.tree.delete(*self.tree.get_children())
        for i, line in enumerate(self.lines):
            parts = line.split(" | ", 2)
            if len(parts) < 3:
                parts = ["", "", line]
            self.tree.insert("", "end", iid=str(i), values=parts)

    def copy_selected(self):
        selected = self.tree.selection()
        if not selected:
            return
        password = self.tree.item(selected[0], "values")[2]
        self.app.clipboard_clear()
        self.app.clipboard_append(password)

    def delete_selected(self):
        selected = {int(i) for i in self.tree.selection()}
        if not selected:
            return
        write_saved([line for i, line in enumerate(self.lines) if i not in selected])
        self.refresh()

    def delete_all(self):
        if self.lines and messagebox.askyesno("Delete all", "Delete all saved passwords?"):
            write_saved([])
            self.refresh()


class App(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("Password Generator")
        self.geometry("700x780")
        self.resizable(False, False)
        self.configure(bg=BG)
        self._setup_style()

        header = tk.Frame(self, bg=BG)
        header.pack(fill="x", padx=24, pady=(20, 14))
        title_row = tk.Frame(header, bg=BG)
        title_row.pack(side="left")
        tk.Label(title_row, text="PASSWORD_GEN", bg=BG, fg=NEON, font=(MONO, 22, "bold")).pack(side="left")
        self.cursor = tk.Label(title_row, text="█", bg=BG, fg=GREEN, font=(MONO, 22, "bold"))
        self.cursor.pack(side="left", padx=(4, 0))
        tk.Label(header, text="● SYSTEM READY", bg=BG, fg=GREEN, font=(MONO, 9, "bold")).pack(side="right", pady=(12, 0))
        tk.Label(self, text="// secure password toolkit", bg=BG, fg=MUTED,
                 font=(MONO, 10)).pack(anchor="w", padx=24)
        tk.Frame(self, bg=NEON, height=2).pack(fill="x", padx=24, pady=(12, 0))

        self.notebook = ttk.Notebook(self)
        self.notebook.pack(fill="both", expand=True, padx=12, pady=(14, 0))
        self.saved_tab = SavedTab(self.notebook, self)
        self.notebook.add(GeneratorTab(self.notebook, self), text="GENERATOR")
        self.notebook.add(PassphraseTab(self.notebook, self), text="PASSPHRASE")
        self.notebook.add(CheckTab(self.notebook, self), text="CHECK")
        self.notebook.add(self.saved_tab, text="SAVED")

        ttk.Label(self, text="// crack time assumes 10 billion guesses per second. strength is an estimate.",
                  style="Footer.TLabel").pack(pady=10)
        self._cursor_on = True
        self._blink()

    def _blink(self):
        self._cursor_on = not self._cursor_on
        self.cursor.config(fg=GREEN if self._cursor_on else BG)
        self.after(550, self._blink)

    def refresh_saved(self):
        self.saved_tab.refresh()

    def _setup_style(self):
        style = ttk.Style(self)
        style.theme_use("clam")
        style.configure(".", background=PANEL, foreground=TEXT, font=(MONO, 10),
                        bordercolor=BORDER, focuscolor=PANEL)
        style.configure("TFrame", background=PANEL)
        style.configure("TLabel", background=PANEL, foreground=TEXT, font=(MONO, 10))
        style.configure("Caption.TLabel", foreground=MUTED, font=(MONO, 9, "bold"))
        style.configure("Level.TLabel", font=(MONO, 13, "bold"))
        style.configure("Value.TLabel", font=(MONO, 12, "bold"), foreground=NEON)
        style.configure("Info.TLabel", foreground=TEXT)
        style.configure("Tip.TLabel", foreground=AMBER)
        style.configure("Ok.TLabel", foreground=GREEN, font=(MONO, 9, "bold"))
        style.configure("Footer.TLabel", background=BG, foreground=MUTED, font=(MONO, 9))

        style.configure("TCheckbutton", background=PANEL, foreground=TEXT, indicatorcolor=FIELD,
                        upperbordercolor=BORDER, lowerbordercolor=BORDER)
        style.map("TCheckbutton", background=[("active", PANEL)], foreground=[("active", NEON)],
                  indicatorcolor=[("selected", NEON), ("pressed", NEON)])

        style.configure("TNotebook", background=BG, borderwidth=0)
        style.configure("TNotebook.Tab", background=BG, foreground=MUTED, padding=(22, 10),
                        font=(MONO, 10, "bold"), borderwidth=0)
        style.map("TNotebook.Tab", background=[("selected", PANEL)],
                  foreground=[("selected", NEON), ("active", TEXT)])

        style.configure("TButton", background=PANEL2, foreground=NEON, bordercolor=BORDER,
                        lightcolor=PANEL2, darkcolor=PANEL2, padding=8, font=(MONO, 10, "bold"))
        style.map("TButton", background=[("active", "#1d2b40")], bordercolor=[("active", NEON)],
                  foreground=[("pressed", GREEN)])
        style.configure("Accent.TButton", background=NEON, foreground="#001018", bordercolor=NEON,
                        lightcolor=NEON, darkcolor=NEON, padding=12, font=(MONO, 11, "bold"))
        style.map("Accent.TButton", background=[("active", GREEN)], bordercolor=[("active", GREEN)],
                  lightcolor=[("active", GREEN)], darkcolor=[("active", GREEN)],
                  foreground=[("active", "#001018")])

        style.configure("Horizontal.TScale", background=NEON, troughcolor=PANEL2, bordercolor=BORDER,
                        lightcolor=NEON, darkcolor=NEON)
        style.configure("TSpinbox", fieldbackground=FIELD, foreground=GREEN, background=PANEL2,
                        arrowcolor=NEON, bordercolor=BORDER, insertcolor=NEON, selectbackground=SELECT)
        style.configure("Treeview", background=FIELD, fieldbackground=FIELD, foreground=TEXT,
                        rowheight=28, borderwidth=0, font=(MONO, 10))
        style.configure("Treeview.Heading", background=PANEL2, foreground=NEON, relief="flat",
                        font=(MONO, 9, "bold"))
        style.map("Treeview", background=[("selected", SELECT)], foreground=[("selected", NEON)])
        style.map("Treeview.Heading", background=[("active", "#1d2b40")])
        style.configure("Vertical.TScrollbar", background=PANEL2, troughcolor=BG, bordercolor=BG,
                        arrowcolor=NEON, gripcount=0)


if __name__ == "__main__":
    App().mainloop()
