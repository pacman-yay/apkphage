import sys
import threading
import time
from contextlib import contextmanager

_SPIN = "|/-\\"


@contextmanager
def _spinner(label: str):
    """Rotating in-place loader shown while the LLM call blocks.

    LLM API calls routinely take 10-60s; without this the terminal sits
    frozen on the last [*] line. The spinner proves the call is alive."""
    stop = threading.Event()

    def _animate():
        i = 0
        while not stop.wait(0.5):
            i += 1
            sys.stdout.write(f"\r  {label} {_SPIN[i % 4]}  ")
            sys.stdout.flush()
        sys.stdout.write("\r" + " " * 40 + "\r")
        sys.stdout.flush()

    t = threading.Thread(target=_animate, daemon=True)
    t.start()
    try:
        yield
    finally:
        stop.set()


def call_llm(prompt: str, retries: int = 3, backoff: float = 5.0) -> str:
    """Call the configured LLM provider with retry on transient errors.

    The pipeline is Groq-only. Retries with exponential backoff on
    503/429 instead of crashing the pipeline.
    """
    last_err = None

    for attempt in range(retries):
        try:
            with _spinner("calling Groq"):
                from groq import Groq

                client = Groq()
                response = client.chat.completions.create(
                    model="llama3-70b-8192",
                    messages=[{"role": "user", "content": prompt}],
                    temperature=0.2,
                )
                return response.choices[0].message.content
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
