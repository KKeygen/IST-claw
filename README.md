# Reproduction package

The datasets are provided in JSON Lines format. Each line contains one JSON object.

## Data files

| File | Unit of observation | Contents |
| --- | --- | --- |
| `00_frozen_records.jsonl` | One unique project, source, and record ID | Source identifiers and, where available, hashes of issue comments. |
| `01_collection_hits.jsonl` | One collection hit | Source identifiers, titles, bodies, and retrieved comments. Repeated hits are retained. |
| `02_screened_candidates.jsonl` | One merged candidate | Screening outcome and links to source records. |
| `03_annotated_findings.jsonl` | One included finding | Classification labels, source links, and analysis fields. |
| `04_repair_evidence.jsonl` | One repair-evidence record | Repair status, mechanism labels, and available external evidence. |
| `05_source_metadata.jsonl` | One unique project, source, and record ID | Source-provided identifiers, severity assessments, CVSS, CWE, version information, and references, where available. |
| `06_patch_references.jsonl` | One repair-evidence record | Available URLs of patch artifacts associated with the repair record. |

## Relationships and fields

`project` distinguishes `OpenClaw` from `Hermes`. Use it together with the record identifier when joining files. The `source_records` fields in the candidate and finding datasets refer to the source names and record IDs in `01_collection_hits.jsonl`. Hits, candidates, findings, and repair records are different units of observation.

`05_source_metadata.jsonl` uses the same project, source, and record ID as `01_collection_hits.jsonl`. Its `source_metadata` array retains distinct available source records and their source-specific field names. In `06_patch_references.jsonl`, `project`, `finding_id`, and `repair_id` identify the corresponding record in `04_repair_evidence.jsonl`.

Classification labels use the English category names in the manuscript. Fields representing a primary category contain one value; `source_memberships` and `mechanisms` may contain multiple values.

## Text and missing values

External text is retained in its original language. Missing text is represented by `null`. For issue comments, `null` means that no comment response was available; an empty array indicates an empty captured response or a reported count of zero. A captured comment list is not necessarily complete.

Source metadata preserves the original source's assessment and version structures; it does not supply an assessment where the source has none. References are source-provided links and do not by themselves establish that a linked change is a security fix. A `null` value for `patch_references` means no patch URL is available in that repair record's evidence.

Repair evidence may include titles, bodies, descriptions, summaries, and pull request text. Available evidence does not necessarily include the complete patch or discussion.
