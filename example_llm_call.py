import os
import time


def call_llm(prompt: str, retries: int = 3, backoff: float = 5.0) -> str:
    """Call the configured LLM provider with retry on transient errors.

    Gemini returns 503/429 during demand spikes. This retries with
    exponential backoff instead of crashing the pipeline.
    """
    provider = os.environ.get("LLM_PROVIDER", "gemini").lower()
    last_err = None

    for attempt in range(retries):
        try:
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
        except Exception as e:
            last_err = e
            err_str = str(e).lower()
            # Only retry on transient / rate-limit errors
            if "503" in err_str or "429" in err_str or "unavailable" in err_str:
                wait = backoff * (2**attempt)
                print(
                    f"    [!] LLM returned transient error ({e.__class__.__name__}), "
                    f"retry {attempt + 1}/{retries} in {int(wait)}s...",
                    flush=True,
                )
                time.sleep(wait)
            else:
                # Permanent error — don't retry
                raise

    raise last_err  # type: ignore[misc]
