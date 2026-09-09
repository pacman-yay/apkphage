import os


def call_llm(prompt: str) -> str:
    provider = os.environ.get("LLM_PROVIDER", "gemini").lower()

    if provider == "groq":
        from groq import Groq

        client = Groq()
        response = client.chat.completions.create(
            model="llama3-70b-8192",
            messages=[{"role": "user", "content": prompt}],
            temperature=0.2,
        )
        return response.choices[0].message.content
    else:
        from google import genai

        client = genai.Client()
        response = client.models.generate_content(
            model="gemini-3.5-flash",
            contents=prompt,
        )
        return response.text
