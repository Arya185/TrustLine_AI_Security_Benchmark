import os
from openai import OpenAI

client = OpenAI(
    api_key=os.environ["OPENROUTER_API_KEY"],
    base_url="https://openrouter.ai/api/v1",
)

model = "gpt-4o-mini-2024-07-18"

try:
    response = client.chat.completions.create(
        model=model,
        messages=[{"role": "user", "content": "Reply with exactly: MODEL_CHECK_OK"}],
        max_tokens=20,
        temperature=0,
    )
    print("Model request: SUCCESS")
    print("Returned model:", response.model)
    print("Response:", repr(response.choices[0].message.content))
except Exception as exc:
    print("Model request: FAILED")
    print("Error type:", type(exc).__name__)
    print("Error:", str(exc)[:1000])