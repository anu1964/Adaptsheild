import glob, os, time, importlib, pkgutil
import document_engine.detectors as pkg

# ---- auto-discover detectors: any function named detect_<ext>_threats ----
HANDLERS = {}
for m in pkgutil.iter_modules(pkg.__path__):
    if not m.name.endswith("_detector"):
        continue
    try:
        mod = importlib.import_module(f"document_engine.detectors.{m.name}")
    except Exception as e:
        print(f"Could not import {m.name}: {e}")
        continue
    for name in dir(mod):
        if name.startswith("detect_") and name.endswith("_threats"):
            ext = "." + name[len("detect_"):-len("_threats")]
            HANDLERS[ext] = getattr(mod, name)

print("Detectors found:", sorted(HANDLERS))


def detect(path):
    fn = HANDLERS.get(os.path.splitext(path)[1].lower())
    if fn is None:
        raise RuntimeError("no detector for " + path)
    r = fn(path)
    if r.get("error"):
        raise RuntimeError(r["error"])
    return r.get("hidden_flags", [])


def run(folder):
    files = glob.glob(os.path.join("dataset", folder, "*"))
    if not files:
        raise SystemExit(f"No files in dataset\\{folder}. Run: python scripts\\make_dataset.py")
    hits, errors, missed, err_msgs = 0, 0, {}, {}
    t = time.perf_counter()
    for f in files:
        key = os.path.basename(f).rsplit("_", 1)[0]
        try:
            if detect(f):
                hits += 1
            else:
                missed[key] = missed.get(key, 0) + 1
        except Exception as e:
            errors += 1
            err_msgs[str(e)[:80]] = err_msgs.get(str(e)[:80], 0) + 1
    avg = (time.perf_counter() - t) / len(files)
    return len(files), hits, errors, avg, missed, err_msgs


mn, mh, me, ml, missed, merr = run("malicious")
cn, ch, ce, cl, false_by_type, cerr = run("clean")

# in the clean folder, a "miss" means correctly not flagged; flagged = hits
print("-" * 44)
print(f"Documents Inspected:         {mn + cn}  ({mn} malicious, {cn} clean)")
print(f"Hidden Content Found:        {mh} of {mn} malicious ({100*mh/mn:.1f}%)")
print(f"False Alarms on Clean Files: {ch} of {cn} ({100*ch/cn:.1f}%)")
print(f"Defense Latency:             {(ml + cl)/2:.3f} s per document")
print(f"Errors (counted as misses):  {me + ce}")
print("-" * 44)
print("Missed, by type_technique:", missed)
if merr or cerr:
    print("Error messages:", {**merr, **cerr})