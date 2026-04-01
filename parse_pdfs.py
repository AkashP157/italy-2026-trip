import fitz  # PyMuPDF
import os
import json

folder = os.path.join(os.path.dirname(__file__), "Bookings")
results = {}

for fname in sorted(os.listdir(folder)):
    if not fname.lower().endswith('.pdf'):
        continue
    path = os.path.join(folder, fname)
    try:
        doc = fitz.open(path)
        text = ""
        for page in doc:
            text += page.get_text() + "\n---PAGE BREAK---\n"
        doc.close()
        results[fname] = text.strip()
    except Exception as e:
        results[fname] = f"ERROR: {e}"

# Output as JSON for easy parsing
print(json.dumps(results, indent=2, ensure_ascii=False))
