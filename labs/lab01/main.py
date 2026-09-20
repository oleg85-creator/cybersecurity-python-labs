"""Головний файл лабораторної роботи №1: демонструє всі три завдання."""

import os
import sys

sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "../../")))

from labs.lab01 import task1, task2, task3
from shared.student import GROUP_NAME, STUDENT_NAME, VARIANT_NUMBER


def main():
    """Послідовно запускає завдання 1, 2 та 3."""
    print("=" * 70)
    print(
        f"Лабораторна робота №1 — {STUDENT_NAME}, "
        f"група {GROUP_NAME}, варіант {VARIANT_NUMBER}"
    )
    print("=" * 70)

    print("\n--- Завдання 1: Аналізатор надійності паролів ---")
    task1.run()

    print("\n--- Завдання 2: Система контролю доступу ---")
    task2.run()

    print("\n--- Завдання 3: Хешування, CSV та JSON-логування ---")
    task3.run()


if __name__ == "__main__":
    main()
