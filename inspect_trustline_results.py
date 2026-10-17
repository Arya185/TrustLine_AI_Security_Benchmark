import json
from pathlib import Path

ROOTS = {
    "baseline": Path("results/trustline-matrix-baseline"),
    "tool_filter": Path("results/trustline-matrix-tool-filter"),
}

TASKS = [
    ("user_task_0", "injection_task_0"),
    ("user_task_14", "injection_task_3"),
    ("user_task_24", "injection_task_6"),
]

for defense, root in ROOTS.items():
    model_dir = (
        "gpt-4o-mini-2024-07-18"
        if defense == "baseline"
        else "gpt-4o-mini-2024-07-18-tool_filter"
    )

    print(f"\n{'=' * 75}")
    print(f"DEFENSE: {defense.upper()}")
    print("=" * 75)

    for user_task, injection_task in TASKS:
        path = (
            root / model_dir / "workspace" / user_task
            / "direct" / f"{injection_task}.json"
        )

        print(f"\n--- {user_task} + {injection_task} ---")

        if not path.exists():
            print("MISSING:", path)
            continue

        data = json.loads(path.read_text())

        print(
            "utility =", data.get("utility"),
            "| security =", data.get("security"),
            "| error =", data.get("error"),
        )

        for i, message in enumerate(data.get("messages", [])):
            print(f"\nMessage {i}:")

            if message.get("role"):
                print("Role:", message["role"])

            # Print available text fields.
            for key in ("content", "text"):
                value = message.get(key)
                if value:
                    print(f"{key}:", str(value)[:2500])

            # Print tool calls, including arguments and results.
            for call in message.get("tool_calls") or []:
                print("Tool call:", json.dumps(call, indent=2)[:2500])

            for key in ("tool_call_id", "name"):
                if message.get(key):
                    print(f"{key}:", message[key])