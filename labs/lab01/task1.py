"""Завдання 1: Комплексний аналізатор надійності паролів (Варіант 9)."""

import os
import random
import sys

sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "../../")))

from shared.student import GROUP_NAME, STUDENT_NAME, VARIANT_NUMBER

# Вхідні дані варіанту 9
passwords = [
    "Digital@F0r3nsics",
    "plain",
    "Encrypt10n@Key",
    "member",
    "Security@Audit2023",
    "regular",
    "Hack3r@D3fense",
    "ordinary",
    "Threat@Intel",
    "usual",
]

criteria = {
    "min_length": 8,
    "require_digits": True,
    "require_upper": True,
    "require_special": True,
}

forbidden_passwords = {"plain", "member", "regular", "ordinary", "usual", "user"}


def duplicate_random_passwords(password_list, count=3):
    """Додає в кінець списку кілька випадково обраних дублікатів паролів."""
    extended_list = list(password_list)
    for _ in range(count):
        random_index = random.randint(0, len(password_list) - 1)
        extended_list.append(password_list[random_index])
    return extended_list


def analyze_password_characters(password):
    """Повертає ознаки наявності цифр, регістру літер та спецсимволів."""
    has_digit = any(char.isdigit() for char in password)
    has_upper = any(char.isupper() for char in password)
    has_lower = any(char.islower() for char in password)
    has_special = any(not char.isalnum() for char in password)
    return has_digit, has_upper, has_lower, has_special


def evaluate_password(password, all_passwords, criteria, forbidden_passwords):
    """Оцінює надійність одного пароля за алгоритмом лабораторної роботи."""
    min_length = criteria["min_length"]
    has_digit, has_upper, has_lower, has_special = analyze_password_characters(password)

    # Заборонений: у чорному списку або коротший за мінімальну довжину
    if password in forbidden_passwords or len(password) < min_length:
        return "Заборонений"

    meets_all_main_criteria = (
        (not criteria["require_digits"] or has_digit)
        and (not criteria["require_upper"] or has_upper)
        and (not criteria["require_special"] or has_special)
    )

    if meets_all_main_criteria:
        # Сильний / Дуже сильний: усі основні критерії виконані
        if len(password) >= min_length + 4:
            is_unique = all_passwords.count(password) == 1
            return "Дуже сильний" if is_unique else "Сильний"
        return "Сильний"

    # Слабкий / Середній: виконано лише частину критеріїв різних груп
    matched_groups = sum([has_digit, has_upper, has_special, has_lower])
    if matched_groups >= 2:
        return "Середній"
    return "Слабкий"


def print_report(evaluated_passwords):
    """Виводить результат аналізу паролів у табличному форматі."""
    print(f"{'№':<4}{'Пароль':<22}{'Рівень надійності':<20}")
    print("-" * 46)
    for index, (password, level) in enumerate(evaluated_passwords, start=1):
        print(f"{index:<4}{password:<22}{level:<20}")


def run():
    """Точка входу для демонстрації роботи завдання 1."""
    print(f"Студент: {STUDENT_NAME}, група: {GROUP_NAME}, варіант: {VARIANT_NUMBER}")

    extended_passwords = duplicate_random_passwords(passwords, count=3)
    evaluated = [
        (
            password,
            evaluate_password(
                password, extended_passwords, criteria, forbidden_passwords
            ),
        )
        for password in extended_passwords
    ]
    print_report(evaluated)


if __name__ == "__main__":
    run()
