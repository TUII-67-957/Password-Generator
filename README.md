# Password Generator

A desktop program with a window that creates strong passwords and checks the strength of any password.
Language: Python 3. Library: tkinter (it comes with Python, nothing to install).

## How to run

```
python main.py
```

On Windows you can also use `py main.py`.

## Design

Dark "tech" style: black background, neon cyan and green colors, Consolas font, a strength bar made of small segments, and a terminal-like result field. All colors are collected at the top of the design part in `main.py` (`BG`, `NEON`, `GREEN` and others), so the theme is easy to change.

## Tabs

| Tab | What it does |
|---|---|
| Generator | Random password: length 8-64, uppercase letters, digits, symbols, option to avoid similar characters (O, 0, l, 1, I) |
| Passphrase | Several random words, for example `Honey-Lilac-Lava-...-56`, easy to remember |
| Check | Shows the strength of any password while you type: bar, entropy, crack time and tips. Button **Save this password** saves it to the list |
| Saved | List of saved passwords, with buttons **Add password** (your own password with a name), Copy, Delete and Delete all |

Every generated result has the buttons **Copy** (to the clipboard) and **Save to file**. You can also save the passwords you already use, in the Saved tab or in the Check tab.

## Algorithms and ideas

- **Secure random numbers:** the program uses the `secrets` module, not `random`. The `random` module is predictable and is not made for passwords.
- **Every selected character type is used:** one character from each chosen group is added first, the rest is taken from the whole pool, then the characters are shuffled.
- **Entropy:** `H = L x log2(N)`, where L is the length and N is the number of possible characters. More bits means a stronger password.
- **Crack time:** brute force needs on average half of all variants: `2^H / 2` guesses. The program assumes 10 billion guesses per second.
- **Common passwords:** a built-in list is checked, and such passwords are marked as very weak.
- **Penalty for repeats:** passwords with many repeated characters get a lower score.
- **Passphrase entropy:** `words x log2(size of the word list)`, plus the bits of the random number at the end.
- **Code structure:** the logic (generation and strength) is in separate functions without any window code, and the window is built from small classes: one for each tab and two shared parts (result box and strength bar).

## Limits

- The strength is an estimate. It assumes random characters, so a password made from words or names (like `Tr0ub4dor&3`) is weaker than the number shows.
- The built-in word list is small, so a passphrase needs about 8 words to be strong.
- Saved passwords are stored as plain text in `saved_passwords.txt`. This is only for demonstration, do not save real passwords.

## Project files

| File | Description |
|---|---|
| `main.py` | The whole program |
| `README.md` | This description |

## Author

IZZATULLO ISMATULLO, group 2518
