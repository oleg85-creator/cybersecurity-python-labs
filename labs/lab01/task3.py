"""Завдання 3: Безпечне хешування, CSV-база та JSON-логування (Варіант 9).

Алгоритм хешування: sha224. Мінімальна довжина пароля: 13 символів.
"""

import csv
import hashlib
import json
import os
import sys
from datetime import datetime
from functools import wraps

sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "../../")))

from shared.student import VARIANT_NUMBER

DATA_DIR = os.path.join(os.path.dirname(__file__), "data")
USERS_CSV_PATH = os.path.join(DATA_DIR, "users.csv")
LOG_JSON_PATH = os.path.join(DATA_DIR, "log.json")

HASH_ALGORITHM = "sha224"
MIN_PASSWORD_LENGTH = 13

# Персональна сіль: варіант 9, доповнений нулями зліва до 5 символів
PERSONAL_SALT = str(VARIANT_NUMBER).zfill(5)

# 10 користувачів для реєстрації (логін, пароль)
users_to_register = (
    ("cloud_architect", "CloudSecure#2024Pass"),
    ("devops_engineer", "DevOpsStr0ng!Pipeline"),
    ("qa_tester", "QaTest1ng@Secure99"),
    ("partner_access", "Partner$Access2024!!"),
    ("migrated_user", "MigrateMe#2024Secure"),
    ("network_admin", "N3tw0rk@AdminPass!"),
    ("data_engineer", "D@taEng1neer2024!"),
    ("security_lead", "Sec#Lead2024Strong!"),
    ("backend_dev", "Backend@Dev2024!!"),
    ("frontend_dev", "Front3nd$Dev2024!!"),
)


class ValidationError(Exception):
    """Власний виняток для помилок валідації пароля."""


def generate_hash(password: str, salt: str = "00000") -> str:
    """Повертає шістнадцятковий хеш конкатенації пароля та солі (sha224)."""
    if not password or not salt:
        raise ValueError("Пароль та сіль не можуть бути порожніми")

    if len(password) < MIN_PASSWORD_LENGTH:
        raise ValidationError(
            f"Довжина пароля має бути не меншою за {MIN_PASSWORD_LENGTH} символів"
        )

    hasher = hashlib.new(HASH_ALGORITHM)
    hasher.update((password + salt).encode("utf-8"))
    return hasher.hexdigest()


def create_user(username, password):
    """Створює запис користувача у вигляді (логін, хеш пароля)."""
    hash_value = generate_hash(password, PERSONAL_SALT)
    return username, hash_value


def create_users(users_list):
    """Обробляє список користувачів та записує їх у CSV-файл users.csv."""
    os.makedirs(DATA_DIR, exist_ok=True)

    try:
        with open(USERS_CSV_PATH, mode="w", newline="", encoding="utf-8") as csv_file:
            writer = csv.writer(csv_file)
            for username, password in users_list:
                try:
                    login_name, hash_value = create_user(username, password)
                    writer.writerow([login_name, hash_value])
                except ValidationError as error:
                    print(f"Пропущено користувача '{username}': {error}")
    except (OSError, PermissionError) as error:
        print(f"Помилка запису файлу users.csv: {error}")


def read_users_db(verbose=True):
    """Зчитує CSV-базу користувачів; за потреби виводить таблицю на екран."""
    try:
        with open(USERS_CSV_PATH, mode="r", newline="", encoding="utf-8") as csv_file:
            reader = csv.reader(csv_file)
            users_db = [tuple(row) for row in reader if row]
    except FileNotFoundError:
        if verbose:
            print("Файл бази користувачів не знайдено. Спочатку виконайте реєстрацію.")
        return []

    if verbose:
        print(f"{'Логін':<20}{'Хеш пароля':<60}")
        print("-" * 80)
        for username, hash_value in users_db:
            print(f"{username:<20}{hash_value:<60}")

    return users_db


def _append_log_entry(entry):
    """Дописує один запис журналу подій у файл log.json."""
    os.makedirs(DATA_DIR, exist_ok=True)

    events = []
    try:
        if os.path.exists(LOG_JSON_PATH):
            with open(LOG_JSON_PATH, mode="r", encoding="utf-8") as log_file:
                events = json.load(log_file)
    except (OSError, json.JSONDecodeError):
        events = []

    events.append(entry)

    try:
        with open(LOG_JSON_PATH, mode="w", encoding="utf-8") as log_file:
            json.dump(events, log_file, ensure_ascii=False, indent=2)
    except (OSError, PermissionError) as error:
        print(f"Помилка запису файлу log.json: {error}")


def log_event(func):
    """Декоратор, що логує кожну спробу входу у файл log.json."""

    @wraps(func)
    def wrapper(*args, **kwargs):
        result = False
        try:
            result = func(*args, **kwargs)
            return result
        finally:
            entry = {
                "event": "login",
                "user": args[0] if args else kwargs.get("username", ""),
                "result": "success" if result else "failure",
                "timestamp": datetime.now().astimezone().strftime("%Y-%m-%d %H:%M:%S"),
                "args": [str(arg) for arg in args[1:]],
                "kwargs": {
                    key: str(value)
                    for key, value in kwargs.items()
                    if key != "password"
                },
            }
            _append_log_entry(entry)

    return wrapper


@log_event
def login(username: str, password: str) -> bool:
    """Перевіряє логін та пароль користувача за даними з CSV-бази."""
    if not username or not password:
        raise ValueError("Логін та пароль не можуть бути порожніми")

    users_db = dict(read_users_db(verbose=False))

    if username not in users_db:
        return False

    expected_hash = users_db[username]
    actual_hash = generate_hash(password, PERSONAL_SALT)
    return expected_hash == actual_hash


def run():
    """Точка входу для демонстрації роботи завдання 3."""
    try:
        create_users(users_to_register)
        read_users_db()

        test_username, test_password = users_to_register[0]

        try:
            success = login(test_username, test_password)
            status = "успішно" if success else "відмовлено"
            print(f"\nВхід користувача '{test_username}': {status}")
        except (ValueError, ValidationError) as error:
            print(f"Помилка входу: {error}")

        try:
            login(test_username, "коротко")
        except ValidationError as error:
            print(f"Очікувана помилка валідації короткого пароля: {error}")

    except (OSError, FileNotFoundError, PermissionError) as error:
        print(f"Помилка роботи з файлами: {error}")


if __name__ == "__main__":
    run()
