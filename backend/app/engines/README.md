# MalvAI Static Engine MVP

This is the first backend engine milestone for Problem Statement 1.

It is a **static engine**, not the full complete engine. It analyzes an APK without running it. The complete engine can later add dynamic sandboxing with emulator, Frida hooks, and network capture.

## What it does

- Validates APK/ZIP input
- Reads APK contents without needing external tools
- Extracts suspicious permissions where visible
- Finds embedded URLs and IP addresses
- Finds banking/fraud-sensitive keywords
- Finds suspicious Android/API strings
- Calculates a risk score and verdict
- Optionally sends findings to Gemini for a human-readable report

## Files

- `static.py`: main `analyze_apk(apk_path)` function
- `scoring.py`: risk score rules
- `genai.py`: Gemini report generation with local fallback
- `__init__.py`: exports the engine function

## Usage

From the project root:

```bash
python -m backend.app.engines.static path/to/app.apk
```

Skip AI/network calls:

```bash
python -m backend.app.engines.static path/to/app.apk --no-ai
```

Use inside FastAPI routes later:

```python
from backend.app.engines import analyze_apk

report = analyze_apk("/tmp/uploaded.apk")
```

## Gemini

Set this environment variable if you want the GenAI summary:

```bash
GEMINI_API_KEY=your_key_here
```

If no key is set, the engine still returns a deterministic local summary.

