from ollama import chat

MODEL = "qwen3:4b"

SYSTEM_PROMPT = """
You are AILOA, a Linux assistant.

Rules:
- Do not use thinking mode.
- Give short and direct answers.
- Maximum 3 sentences for normal questions.
- For Linux command requests, return only the command.
- Do not execute commands.
- Warn about dangerous commands.
"""


def ask_qwen(prompt):

    try:
        response = chat(
            model=MODEL,
            messages=[
                {
                    "role": "system",
                    "content": SYSTEM_PROMPT
                },
                {
                    "role": "user",
                    "content": prompt
                }
            ],
            think=False,
            stream=False,
            options={
                "temperature": 0.2,
                "num_predict": 60
            }
        )

        return response.message.content

    except Exception as e:
        return f"Qwen connection error: {e}"
