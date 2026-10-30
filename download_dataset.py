
from datasets import load_dataset
import json
import os

os.makedirs("data", exist_ok=True)

print("Loading BIPIA dataset...")

dataset = load_dataset(
    "MAlmasabi/Indirect-Prompt-Injection-BIPIA-GPT",
    split="train"
)

output_file = "data/bipia_dataset.jsonl"

with open(output_file, "w", encoding="utf-8") as f:
    for item in dataset:
        f.write(json.dumps(item, ensure_ascii=False) + "\n")

print("Dataset downloaded successfully!")
print("Total samples:", len(dataset))
print("Saved to:", output_file)
