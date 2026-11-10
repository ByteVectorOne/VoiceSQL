"""Generate demo-video narration clips with Gnani Timbre TTS.

Usage (PowerShell):
    python make_voiceover.py
    (it asks for your key; or set $env:GNANI_API_KEY first to skip the prompt)

Optional: $env:NARRATOR_VOICE="Nalini"   $env:NARRATOR_LANG="hi-en"
Creates narration_01.wav ... narration_06.wav in the current folder.
"""
import getpass
import os
import sys
import requests

KEY = os.getenv("GNANI_API_KEY")
VOICE = os.getenv("NARRATOR_VOICE", "Nalini")
LANG = os.getenv("NARRATOR_LANG", "hi-en")

LINES = [
    "I told my company database to delete everything. It said no.",
    "Ask in Hinglish. Gnani Prisma listens, Gemini writes the SQL, and Gnani Timbre speaks the answer.",
    "Now the Manager role. Ask for a salary, and the database itself refuses.",
    "Now an attack. Delete all employees. Blocked, announced out loud, and logged.",
    "Five layers of security. The AI's SQL is never trusted.",
    "What would you ask your company database?",
]

if not KEY:
    # No environment variable found: ask for the key (typing is hidden, nothing is saved).
    KEY = getpass.getpass("Paste your NEW Gnani API key (hidden), then press Enter: ").strip()
if not KEY:
    sys.exit("No key entered.")

URL = "https://api.vachana.ai/api/v1/tts/inference"
HEADERS = {"X-API-Key-ID": KEY, "Content-Type": "application/json"}

for i, text in enumerate(LINES, start=1):
    payload = {
        "text": text,
        "voice": VOICE,
        "model": "timbre-v2.5",
        "language": LANG,
        "speed": 1.0,
        "audio_config": {"sample_rate": 48000, "num_channels": 1, "sample_width": 2,
                         "encoding": "linear_pcm", "container": "wav"},
    }
    try:
        r = requests.post(URL, headers=HEADERS, json=payload, timeout=60)
        r.raise_for_status()
    except Exception as e:
        print(f"Line {i} failed: {type(e).__name__}: {str(e)[:200].replace(KEY, '***')}")
        continue
    name = f"narration_{i:02d}.wav"
    with open(name, "wb") as f:
        f.write(r.content)
    print(f"Saved {name} ({len(r.content) // 1024} KB): {text}")
