import argparse
import hashlib
import json
from pathlib import Path


def export(input_path, output_path):
    selected = {}
    with Path(input_path).open(encoding='utf-8') as source:
        for line in source:
            item = json.loads(line)
            key = (item['project'], item['source'], str(item['record_id']))
            comments = item.get('comments')
            hashes = None if comments is None else [hashlib.sha256(c.encode('utf-8')).hexdigest() for c in comments]
            entry = {'project': key[0], 'source': key[1], 'record_id': key[2]}
            if key[1] == 'GitHub Issues':
                entry['comment_sha256'] = hashes
            if key in selected and selected[key] != entry:
                raise ValueError('inconsistent frozen records: ' + str(key))
            selected[key] = entry
    with Path(output_path).open('x', encoding='utf-8') as output:
        for entry in selected.values():
            output.write(json.dumps(entry, ensure_ascii=False) + '\n')
    return len(selected)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--input', required=True)
    parser.add_argument('--output', required=True)
    args = parser.parse_args()
    count = export(args.input, args.output)
    print('exported ' + str(count) + ' records to ' + args.output)


if __name__ == '__main__':
    main()
