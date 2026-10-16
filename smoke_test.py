import os
import time
import requests
from pathlib import Path
from dotenv import load_dotenv

load_dotenv(Path(__file__).resolve().parent / ".env")

api_key = os.getenv("OPENROUTER_API_KEY")
if not api_key:
    raise SystemExit("OPENROUTER_API_KEY is missing from .env")

# Choose a model available to your OpenRouter account.
model = os.getenv("TRUSTLINE_MODEL", "openai/gpt-4o-mini")

start = time.perf_counter()

response = requests.post(
    "https://openrouter.ai/api/v1/chat/completions",
    headers={
        "Authorization": f"Bearer {api_key}",
        "Content-Type": "application/json",
        "X-OpenRouter-Title": "TrustLine Benchmark",
    },
    json={
        "model": model,
        "messages": [
            {
                "role": "system",
                "content": "Reply briefly and follow the user's request."
            },
            {
                "role": "user",
                "content": "Reply with exactly: TRUSTLINE_SMOKE_TEST_OK"
            },
        ],
        "temperature": 0,
        "max_tokens": 30,
    },
    timeout=60,
)

elapsed = time.perf_counter() - start

if not response.ok:
    print("Request failed with HTTP status:", response.status_code)
    print("Error:", response.text[:1000])
    raise SystemExit(1)

data = response.json()
message = data["choices"][0]["message"]["content"]

print("API request: SUCCESS")
print("Requested model:", model)
print("Returned model:", data.get("model", "not reported"))
print("Response:", repr(message))
print(f"Elapsed time: {elapsed:.2f}s")
print("Token usage:", data.get("usage", "not reported"))
