"""Завдання 2: Багаторівнева система контролю доступу (Варіант 9)."""

# Вхідні дані варіанту 9
users = {
    "cloud_architect": {
        "role": "cloud_security",
        "clearance": 4,
        "department": "Cloud",
        "active": True,
    },
    "devops_engineer": {
        "role": "devops",
        "clearance": 3,
        "department": "DevOps",
        "active": True,
    },
    "qa_tester": {
        "role": "quality_assurance",
        "clearance": 2,
        "department": "QA",
        "active": True,
    },
    "partner_access": {
        "role": "partner",
        "clearance": 2,
        "department": "Partnership",
        "active": True,
    },
    "migrated_user": {
        "role": "migrated",
        "clearance": 1,
        "department": "Migration",
        "active": False,
    },
}

resources = [
    ("cloud_configs", 4),
    ("deployment_pipelines", 3),
    ("test_environments", 2),
    ("partner_apis", 2),
    ("infrastructure_code", 4),
    ("shared_resources", 1),
    ("container_registry", 3),
    ("secrets_vault", 4),
    ("build_artifacts", 2),
    ("public_endpoints", 1),
]

security_levels = ("Development", "Staging", "Production", "Critical Infrastructure")

blocked_users = {"migrated_user", "container_breach", "pipeline_compromise"}


def level_name(level_number, security_levels):
    """Перетворює числовий рівень безпеки на текстову назву."""
    return security_levels[level_number - 1]


def print_resources(resources, security_levels):
    """Виводить список ресурсів із текстовою назвою рівня безпеки."""
    print("Ресурси системи:")
    for name, level in resources:
        print(f"  {name}: {level_name(level, security_levels)}")
    print()


def check_access(username, required_level, users, blocked_users):
    """Перевіряє доступ користувача до ресурсу та повертає (рішення, причина)."""
    if username not in users:
        return "DENY", "User not found"

    if username in blocked_users:
        return "DENY", "User is blocked"

    user = users[username]

    if not user["active"]:
        return "DENY", "Account inactive"

    if user["clearance"] >= required_level:
        return "ALLOW", ""

    return "DENY", "Insufficient clearance"


def run():
    """Точка входу для демонстрації роботи завдання 2."""
    print_resources(resources, security_levels)

    for username in users:
        for resource_name, required_level in resources:
            decision, reason = check_access(
                username, required_level, users, blocked_users
            )
            if decision == "ALLOW":
                print(f"user={username} resource={resource_name} -> ALLOW")
            else:
                print(f"user={username} resource={resource_name} -> DENY ({reason})")


if __name__ == "__main__":
    run()
