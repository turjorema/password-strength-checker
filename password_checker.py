#!/usr/bin/env python3
"""
Password Strength Checker
--------------------------
A colorful, interactive command-line tool that analyzes password strength
and gives detailed feedback on how to improve it.

Run with:  python password_strength_checker.py
"""

import re
import math


# ---------------------------------------------------------------------------
# Terminal colors (ANSI escape codes) — works on macOS/Linux and modern
# Windows terminals (Windows 10+ / VS Code / Windows Terminal).
# ---------------------------------------------------------------------------
class C:
    RESET = "\033[0m"
    BOLD = "\033[1m"
    DIM = "\033[2m"

    RED = "\033[91m"
    ORANGE = "\033[38;5;208m"
    YELLOW = "\033[93m"
    GREEN = "\033[92m"
    CYAN = "\033[96m"
    MAGENTA = "\033[95m"
    GRAY = "\033[90m"
    WHITE = "\033[97m"


BAR_WIDTH = 40


def strip_ansi(text: str) -> str:
    return re.sub(r"\033\[[0-9;]*m", "", text)


def center(text: str, width: int) -> str:
    """Center text, accounting for invisible ANSI codes."""
    visible_len = len(strip_ansi(text))
    pad = max(width - visible_len, 0)
    left = pad // 2
    right = pad - left
    return " " * left + text + " " * right


def print_box(lines, width=64, color=C.CYAN):
    top = f"{color}╔{'═' * (width - 2)}╗{C.RESET}"
    bottom = f"{color}╚{'═' * (width - 2)}╝{C.RESET}"
    print(top)
    for line in lines:
        inner = center(line, width - 4)
        print(f"{color}║{C.RESET} {inner} {color}║{C.RESET}")
    print(bottom)


# ---------------------------------------------------------------------------
# Scoring engine
# ---------------------------------------------------------------------------
COMMON_PASSWORDS = {
    "password", "123456", "123456789", "qwerty", "abc123", "letmein",
    "monkey", "111111", "iloveyou", "admin", "welcome", "password1",
    "12345678", "sunshine", "princess", "football", "dragon", "master",
}

LEVELS = [
    (0, 20, "Very Weak", C.RED),
    (20, 40, "Weak", C.ORANGE),
    (40, 60, "Fair", C.YELLOW),
    (60, 80, "Strong", C.GREEN),
    (80, 101, "Very Strong", C.MAGENTA),
]


def calc_entropy(password: str) -> float:
    """Estimate entropy in bits based on character pool size and length."""
    pool = 0
    if re.search(r"[a-z]", password):
        pool += 26
    if re.search(r"[A-Z]", password):
        pool += 26
    if re.search(r"[0-9]", password):
        pool += 10
    if re.search(r"[^a-zA-Z0-9]", password):
        pool += 32
    if pool == 0:
        return 0.0
    return len(password) * math.log2(pool)


def analyze_password(password: str):
    checks = []
    score = 0

    length = len(password)

    # --- Length scoring ---
    if length >= 16:
        score += 30
        checks.append((True, f"Excellent length ({length} characters)"))
    elif length >= 12:
        score += 22
        checks.append((True, f"Good length ({length} characters)"))
    elif length >= 8:
        score += 12
        checks.append((True, f"Acceptable length ({length} characters)"))
    else:
        checks.append((False, f"Too short ({length} characters) — use 12+"))

    # --- Character variety ---
    has_lower = bool(re.search(r"[a-z]", password))
    has_upper = bool(re.search(r"[A-Z]", password))
    has_digit = bool(re.search(r"[0-9]", password))
    has_symbol = bool(re.search(r"[^a-zA-Z0-9]", password))

    variety = sum([has_lower, has_upper, has_digit, has_symbol])
    score += variety * 10

    checks.append((has_lower, "Contains lowercase letters"))
    checks.append((has_upper, "Contains uppercase letters"))
    checks.append((has_digit, "Contains numbers"))
    checks.append((has_symbol, "Contains special characters (!@#$...)"))

    # --- Patterns / weaknesses ---
    has_repeats = bool(re.search(r"(.)\1{2,}", password))
    has_sequence = bool(
        re.search(
            r"(0123|1234|2345|3456|4567|5678|6789|"
            r"abcd|bcde|cdef|defg|qwer|asdf|zxcv)",
            password.lower(),
        )
    )
    is_common = password.lower() in COMMON_PASSWORDS

    if has_repeats:
        score -= 10
        checks.append((False, "Avoid repeated characters (e.g. 'aaa')"))
    else:
        checks.append((True, "No repeated character runs"))

    if has_sequence:
        score -= 10
        checks.append((False, "Avoid sequential patterns (e.g. '1234', 'qwer')"))
    else:
        checks.append((True, "No obvious sequential patterns"))

    if is_common:
        score -= 30
        checks.append((False, "This is a commonly used password!"))
    else:
        checks.append((True, "Not found in common password list"))

    # --- Entropy bonus ---
    entropy = calc_entropy(password)
    if entropy >= 60:
        score += 10

    score = max(0, min(100, score))
    return score, entropy, checks


def get_level(score: int):
    for low, high, label, color in LEVELS:
        if low <= score < high:
            return label, color
    return "Very Strong", C.MAGENTA


def render_bar(score: int, color: str) -> str:
    filled = int((score / 100) * BAR_WIDTH)
    empty = BAR_WIDTH - filled
    return f"{color}{'█' * filled}{C.GRAY}{'░' * empty}{C.RESET}"


def crack_time_estimate(entropy: float) -> str:
    """Very rough offline brute-force estimate at 10 billion guesses/sec."""
    if entropy <= 0:
        return "instantly"
    guesses = 2 ** entropy
    seconds = guesses / 1e10

    units = [
        ("seconds", 60),
        ("minutes", 60),
        ("hours", 24),
        ("days", 365),
        ("years", 100),
        ("centuries", float("inf")),
    ]
    value = seconds
    unit_name = "seconds"
    for name, factor in units:
        unit_name = name
        if value < factor:
            break
        value /= factor

    if unit_name == "centuries" and value > 1e6:
        return "essentially forever"
    return f"~{value:,.1f} {unit_name}"


def print_report(password: str):
    score, entropy, checks = analyze_password(password)
    label, color = get_level(score)
    crack_time = crack_time_estimate(entropy)

    print()
    print_box([f"{C.BOLD}PASSWORD STRENGTH REPORT{C.RESET}"], color=C.CYAN)
    print()

    bar = render_bar(score, color)
    print(f"  Score      : {color}{C.BOLD}{score}/100{C.RESET}")
    print(f"  Strength   : {color}{C.BOLD}{label}{C.RESET}")
    print(f"  Meter      : {bar}")
    print(f"  Entropy    : {C.WHITE}{entropy:.1f} bits{C.RESET}")
    print(f"  Est. crack time (offline attack): {C.WHITE}{crack_time}{C.RESET}")
    print()

    print(f"  {C.BOLD}Details:{C.RESET}")
    for passed, message in checks:
        icon = f"{C.GREEN}✔{C.RESET}" if passed else f"{C.RED}✘{C.RESET}"
        print(f"    {icon}  {message}")

    print()
    if score < 60:
        print(f"  {C.YELLOW}💡 Tip:{C.RESET} Try a longer passphrase mixing words, "
              f"numbers, and symbols — e.g. 'Sunset-River47!Kite'")
    else:
        print(f"  {C.GREEN}🎉 Nice! This password looks solid.{C.RESET}")
    print()


def print_banner():
    print()
    print_box(
        [
            f"{C.BOLD}🔐  PASSWORD STRENGTH CHECKER  🔐{C.RESET}",
            f"{C.YELLOW}v1.0{C.RESET}",
            f"{C.DIM}Type 'quit' to exit{C.RESET}",
            f"{C.MAGENTA}{C.BOLD}Developed by Turjo Rema {C.CYAN}(4rch-M3g){C.RESET}",
        ],
        color=C.MAGENTA,
    )


def main():
    print_banner()
    while True:
        print()
        try:
            password = input(
                f"{C.CYAN}Enter a password to analyze > {C.RESET}"
            )
        except (EOFError, KeyboardInterrupt):
            print(f"\n{C.DIM}Goodbye!{C.RESET}")
            break

        if password.lower() in ("quit", "exit"):
            print(f"{C.DIM}Goodbye!{C.RESET}")
            break

        if not password:
            print(f"{C.RED}Please enter a password.{C.RESET}")
            continue

        print_report(password)


if __name__ == "__main__":
    main()