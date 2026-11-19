import json
import os

FINGERPRINTS_DIR = "webappanalyzer/src/technologies"
CATEGORIES_FILE = "webappanalyzer/src/categories.json"

def load_fingerprints():
    fingerprints = {}
    files = sorted(os.listdir(FINGERPRINTS_DIR))

    for filename in files:
        if not filename.endswith(".json"):          
            continue
        path = os.path.join(FINGERPRINTS_DIR, filename)   
        with open(path, encoding="utf-8") as f:
            fingerprints.update(json.load(f))

    print(f"There are {len(files)} folders, with {len(fingerprints)} technologies.")
    return fingerprints


def load_categories():
    with open(CATEGORIES_FILE, encoding="utf-8") as f:
        return json.load(f)

def show_technology(name, fingerprints, categories):
    matches = []
    for t in fingerprints:
        if t.lower() == name.lower():
            matches.append(t)
    if not matches:
        print("we didn't find this technology into the database")
        return
    tech = matches[0]
    rules = fingerprints[tech]
    categories_name = [categories[str(c)]["name"] for c in rules.get("cats", [])]
    print(f"{tech}")
    print(f"Category:{categories_name}")
    print("Fields:")
    for key,values in rules.items():
        print(f"{key}:{values}")

if __name__ == "__main__":
    finger_print = load_fingerprints()
    print(json.dumps(finger_print["WordPress"], indent=2, ensure_ascii=False))
    categories = load_categories()
    show_technology("WordPress",finger_print,categories)