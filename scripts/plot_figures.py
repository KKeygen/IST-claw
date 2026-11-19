import argparse
import json
from collections import Counter
from pathlib import Path

import matplotlib

matplotlib.use("Agg")

import matplotlib.pyplot as plt
import numpy as np


SURFACES = [
    "Authentication & Authorization",
    "Network",
    "Code Execution",
    "File System",
    "Supply Chain",
    "Context Manipulation",
    "Client-Side",
    None,
]

CAUSES = [
    "Missing validation",
    "Design flaw",
    "Insecure defaults",
    "Logic error",
    "Insufficient authentication/authorization",
    "Information disclosure",
    "Dependency defect",
    "Context trust failure",
    None,
]

SOURCES = ["GHSA", "NVD", "OpenCVE", "Community CSV", "GitHub Issues"]


def load_jsonl(path):
    with path.open(encoding="utf-8") as file:
        return [json.loads(line) for line in file if line.strip()]


def plot_surface_rootcause(findings, output_dir):
    figure, axes = plt.subplots(1, 2, figsize=(16, 6.7), layout="constrained")

    for axis, project in zip(axes, ["OpenClaw", "Hermes"]):
        counts = Counter(
            (finding["attack_surface"], finding["root_cause"])
            for finding in findings
            if finding["project"] == project
        )
        matrix = np.array(
            [[counts[surface, cause] for cause in CAUSES] for surface in SURFACES]
        )
        totals = matrix.sum(axis=1, keepdims=True)
        shares = np.divide(
            matrix,
            totals,
            out=np.zeros_like(matrix, dtype=float),
            where=totals != 0,
        )
        axis.imshow(shares, vmin=0, vmax=1, cmap="Blues", aspect="auto")

        for row in range(len(SURFACES)):
            for column in range(len(CAUSES)):
                if not totals[row, 0]:
                    label = "N/A"
                else:
                    label = str(matrix[row, column]) if matrix[row, column] else "–"
                color = "white" if shares[row, column] > 0.55 else "black"
                axis.text(
                    column, row, label, ha="center", va="center", fontsize=8, color=color
                )

        surface_labels = [
            f'{surface or "Unknown"} ({totals[index, 0]})'
            for index, surface in enumerate(SURFACES)
        ]
        axis.set_title(f"{project} (n={sum(totals[:, 0])})")
        axis.set_yticks(range(len(SURFACES)), surface_labels)
        axis.set_xticks(range(len(CAUSES)), [str(i) for i in range(1, 9)] + ["?"])
        axis.set_xlabel("Root cause code")

    figure.suptitle(
        "Surface × root cause; color = within-surface share\n"
        "1 Validation · 2 Design · 3 Defaults · 4 Logic · 5 Auth · "
        "6 Disclosure · 7 Dependency · 8 Context · ? Unknown",
        fontsize=11,
    )
    figure.savefig(output_dir / "surface-rootcause-reproduction.png", dpi=180)
    plt.close(figure)


def plot_screening_flow(records, candidates, findings, output_dir):
    sources = Counter(record["source"] for record in records)
    dispositions = Counter(candidate["disposition"] for candidate in candidates)
    projects = Counter(candidate["project"] for candidate in candidates)
    paths = Counter(finding["propagation_case"] for finding in findings)

    boxes = [
        ("Unique source records", "\n".join(f"{name}: {sources[name]}" for name in SOURCES)),
        (
            "Candidates",
            f"OpenClaw: {projects['OpenClaw']}\n"
            f"Hermes: {projects['Hermes']}\n"
            f"Total: {sum(projects.values())}",
        ),
        (
            "Screening",
            f"Retained: {dispositions['Retained']}\n"
            f"Duplicate/withdrawn: {dispositions['Duplicate or withdrawn']}\n"
            f"Other exclusions: {dispositions['Excluded']}",
        ),
        (
            "Analysis",
            f"Path cases: {paths[True]}\n"
            f"Other cases: {paths[False]}\n"
            f"Total: {len(findings)}",
        ),
    ]

    figure, axis = plt.subplots(figsize=(12, 3.8), layout="constrained")
    axis.axis("off")

    for index, (title, body) in enumerate(boxes):
        x = 0.02 + index * 0.25
        axis.text(
            x + 0.105, 0.86, title,
            ha="center", weight="bold", transform=axis.transAxes,
        )
        axis.text(
            x + 0.105, 0.48, body,
            ha="center", va="center", fontsize=10, transform=axis.transAxes,
            bbox={"boxstyle": "round,pad=0.7", "facecolor": "#e8f1f7", "edgecolor": "#456"},
        )
        if index < len(boxes) - 1:
            axis.annotate(
                "", xy=(x + 0.245, 0.48), xytext=(x + 0.215, 0.48),
                xycoords="axes fraction", arrowprops={"arrowstyle": "->", "lw": 1.5},
            )

    figure.savefig(output_dir / "screening-flow-reproduction.png", dpi=180)
    plt.close(figure)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--input-dir", type=Path, required=True)
    parser.add_argument("--output-dir", type=Path, required=True)
    args = parser.parse_args()

    records = load_jsonl(args.input_dir / "00_frozen_records.jsonl")
    candidates = load_jsonl(args.input_dir / "02_screened_candidates.jsonl")
    findings = load_jsonl(args.input_dir / "03_annotated_findings.jsonl")
    args.output_dir.mkdir(parents=True, exist_ok=True)

    plot_surface_rootcause(findings, args.output_dir)
    plot_screening_flow(records, candidates, findings, args.output_dir)


if __name__ == "__main__":
    main()
