import argparse
import collections
import datetime as dt
import hashlib
import json
import os
import re
import sys
import time
from pathlib import Path
from urllib.error import HTTPError, URLError
from urllib.parse import urlencode, urlparse
from urllib.request import Request, urlopen
from export_freeze import export
from source_metadata import community_metadata, project_metadata

PROJECTS = {
    'OpenClaw': {'repo': 'openclaw/openclaw', 'start': '2025-11-24', 'keyword': 'openclaw', 'vendor': 'openclaw', 'product': None},
    'Hermes': {'repo': 'NousResearch/hermes-agent', 'start': '2025-07-22', 'keyword': 'hermes-agent', 'vendor': 'nousresearch', 'product': 'hermes-agent'},
}
SOURCES = ('GHSA', 'GitHub Issues', 'NVD', 'OpenCVE', 'Community CSV')
TERMS = ('is:issue label:security', 'is:issue label:vulnerability', 'is:issue "CVE" in:title', 'is:issue "RCE" in:title', 'is:issue "injection" in:title', 'is:issue "privilege escalation" in:title', 'is:issue "arbitrary file" in:title', 'is:issue "path traversal" in:title', 'is:issue "security vulnerability" in:body', 'is:issue "SSRF" in:title', 'is:issue "authentication bypass" in:title', 'is:issue "XSS" in:title')
ROOT = Path(__file__).resolve().parent.parent
last_nvd = 0.0


def load_config():
    path = ROOT / '.env'
    if not path.exists():
        return
    for line in path.read_text(encoding='utf-8').splitlines():
        key, separator, value = line.partition('=')
        key = key.strip()
        if separator and key in ('GITHUB_TOKEN', 'NVD_API_KEY', 'OPENCVE_TOKEN'):
            os.environ.setdefault(key, value.strip().strip('"\''))


def request(url, source):
    global last_nvd
    headers = {'User-Agent': 'IST-data-collection/1.0', 'Accept': 'application/json'}
    if source in ('GHSA', 'GitHub Issues'):
        headers['Accept'] = 'application/vnd.github+json'
        headers['X-GitHub-Api-Version'] = '2022-11-28'
        if os.environ.get('GITHUB_TOKEN'):
            headers['Authorization'] = 'Bearer ' + os.environ['GITHUB_TOKEN']
    if source == 'NVD':
        time.sleep(max(0, 6 - (time.monotonic() - last_nvd)))
        last_nvd = time.monotonic()
        if os.environ.get('NVD_API_KEY'):
            headers['apiKey'] = os.environ['NVD_API_KEY']
    if source == 'OpenCVE':
        token = os.environ.get('OPENCVE_TOKEN')
        if not token:
            raise RuntimeError('OpenCVE requires OPENCVE_TOKEN')
        headers['Authorization'] = 'Bearer ' + token
    try:
        with urlopen(Request(url, headers=headers), timeout=45) as response:
            text = response.read().decode('utf-8')
            return (text if source == 'Community CSV' else json.loads(text)), response.headers
    except HTTPError as exc:
        raise RuntimeError('HTTP ' + str(exc.code) + ' while accessing ' + source) from None
    except (URLError, TimeoutError, OSError, ValueError):
        raise RuntimeError('request or response failed for ' + source) from None


def row(project, source, record_id, title, body, comments=None, metadata=None):
    return {'project': project, 'source': source, 'record_id': str(record_id), 'title': title, 'body': body, 'comments': comments, 'source_metadata': metadata}


def issue_links(repo, number, cutoff=None):
    result = []
    page = 1
    while True:
        url = 'https://api.github.com/repos/' + repo + '/issues/' + str(number) + '/timeline?' + urlencode({'per_page': 100, 'page': page})
        data, headers = request(url, 'GitHub Issues')
        if not isinstance(data, list):
            raise RuntimeError('unexpected issue timeline response')
        for event in data:
            created = event.get('created_at')
            if cutoff and (not created or created[:10] >= cutoff):
                continue
            linked = (event.get('source') or {}).get('issue') or {}
            links = [event.get('commit_url')]
            if 'pull_request' in linked:
                links.append(linked.get('html_url'))
            for link in links:
                if isinstance(link, str) and link:
                    entry = {'event': event.get('event'), 'created_at': created, 'url': link}
                    if entry not in result:
                        result.append(entry)
        if 'rel="next"' not in headers.get('Link', ''):
            break
        page += 1
    return result


def issue_comments(repo, number, expected=None):
    found = []
    remaining = collections.Counter(expected) if expected is not None else None
    page = 1
    while remaining is None or remaining:
        url = 'https://api.github.com/repos/' + repo + '/issues/' + str(number) + '/comments?' + urlencode({'per_page': 100, 'page': page})
        data, headers = request(url, 'GitHub Issues')
        if not isinstance(data, list):
            raise RuntimeError('unexpected issue comments response')
        for item in data:
            body = item.get('body') or ''
            if remaining is None:
                found.append(body)
            else:
                digest = hashlib.sha256(body.encode('utf-8')).hexdigest()
                if not remaining[digest]:
                    continue
                found.append(body)
                remaining[digest] -= 1
                if remaining[digest] == 0:
                    del remaining[digest]
        if 'rel="next"' not in headers.get('Link', ''):
            break
        page += 1
    return found


def issues(project, cutoff):
    repo = PROJECTS[project]['repo']
    start = dt.date.fromisoformat(PROJECTS[project]['start'])
    end = dt.date.fromisoformat(cutoff) - dt.timedelta(days=1)
    comments = {}
    links = {}
    def search(term, first, last, supplemental=False):
        q = 'repo:' + repo + ' ' + term + ' created:' + first.isoformat() + '..' + last.isoformat()
        if supplemental:
            q += ' closed:<=' + end.isoformat()
        def page(n):
            return request('https://api.github.com/search/issues?' + urlencode({'q': q, 'per_page': 100, 'page': n}), 'GitHub Issues')[0]
        data = page(1)
        if data.get('incomplete_results'):
            raise RuntimeError('GitHub reported incomplete search results')
        count = data['total_count']
        if count >= 1000:
            if first == last:
                raise RuntimeError('GitHub search reaches 1000 results in one day')
            middle = first + (last - first) // 2
            yield from search(term, first, middle, supplemental)
            yield from search(term, middle + dt.timedelta(days=1), last, supplemental)
            return
        for n in range(1, (count + 99) // 100 + 1):
            current = data if n == 1 else page(n)
            if current.get('incomplete_results'):
                raise RuntimeError('GitHub reported incomplete search results')
            for item in current.get('items', []):
                if 'pull_request' not in item:
                    if supplemental:
                        labels = [label.get('name', '') for label in item.get('labels', []) if isinstance(label, dict)]
                        created = item.get('created_at') or ''
                        closed = item.get('closed_at') or ''
                        if (item.get('state') != 'closed' or item.get('state_reason') != 'completed'
                                or 'type/security' not in [label.lower() for label in labels]
                                or not created or created[:10] >= cutoff
                                or not closed or closed[:10] >= cutoff):
                            continue
                    number = item['number']
                    if number not in comments:
                        comments[number] = issue_comments(repo, number) if item.get('comments') else []
                        links[number] = issue_links(repo, number, cutoff)
                    metadata = project_metadata('GitHub Issues', item)
                    metadata['linked_changes'] = links[number]
                    result = row(project, 'GitHub Issues', number, item.get('title'), item.get('body'), comments[number], metadata)
                    if supplemental:
                        result.update({'labels': labels, 'state': item['state'], 'state_reason': item['state_reason'],
                                       'created_at': created, 'closed_at': closed})
                    yield result
    terms = [(term, False) for term in TERMS]
    if project == 'Hermes':
        terms.append(('is:issue is:closed reason:completed label:type/security', True))
    for term, supplemental in terms:
        current = start
        while current <= end:
            last = min(dt.date(current.year, 12, 31), end)
            yield from search(term, current, last, supplemental)
            current = last + dt.timedelta(days=1)


def advisories(project, cutoff):
    repo = PROJECTS[project]['repo']
    page = 1
    if project == 'Hermes':
        params = {'type': 'reviewed', 'affects': 'hermes-agent', 'per_page': 100, 'sort': 'published', 'direction': 'asc'}
        url = 'https://api.github.com/advisories?' + urlencode(params)
        while url:
            data, headers = request(url, 'GHSA')
            if not isinstance(data, list):
                raise RuntimeError('unexpected GHSA response')
            for item in data:
                published = item.get('published_at') or ''
                locations = [item.get('source_code_location'), item.get('repository_advisory_url')]
                locations.extend(x if isinstance(x, str) else x.get('url') for x in item.get('references') or [] if isinstance(x, (str, dict)))
                repo_match = any(isinstance(link, str) and ('github.com/' + repo.lower()) in link.lower() for link in locations)
                if repo_match and published and published[:10] < cutoff:
                    yield row(project, 'GHSA', item['ghsa_id'], item.get('summary'), item.get('description'), metadata=project_metadata('GHSA', item))
            match = re.search(r'<([^>]+)>;\s*rel="next"', headers.get('Link', ''))
            url = match.group(1) if match else None
            if url and (urlparse(url).scheme != 'https' or urlparse(url).netloc != 'api.github.com'):
                raise RuntimeError('unexpected advisory pagination URL')
            if data and (data[-1].get('published_at') or '')[:10] >= cutoff:
                break
        return
    while True:
        url = 'https://api.github.com/repos/' + repo + '/security-advisories?' + urlencode({'per_page': 100, 'page': page, 'sort': 'published', 'direction': 'asc'})
        data, headers = request(url, 'GHSA')
        if not isinstance(data, list):
            raise RuntimeError('unexpected GHSA response')
        for item in data:
            published = item.get('published_at') or ''
            if published and published[:10] < cutoff:
                yield row(project, 'GHSA', item['ghsa_id'], item.get('summary'), item.get('description'), metadata=project_metadata('GHSA', item))
        if 'rel="next"' not in headers.get('Link', '') or not data:
            break
        if (data[-1].get('published_at') or '')[:10] >= cutoff:
            break
        page += 1


def nvd(project, cutoff):
    start = dt.date.fromisoformat(PROJECTS[project]['start'])
    end = dt.date.fromisoformat(cutoff) - dt.timedelta(days=1)
    while start <= end:
        stop = min(start + dt.timedelta(days=119), end)
        offset = 0
        while True:
            params = {'keywordSearch': PROJECTS[project]['keyword'], 'pubStartDate': start.isoformat() + 'T00:00:00.000', 'pubEndDate': stop.isoformat() + 'T23:59:59.999', 'resultsPerPage': 2000, 'startIndex': offset}
            data, _ = request('https://services.nvd.nist.gov/rest/json/cves/2.0?' + urlencode(params), 'NVD')
            records = data.get('vulnerabilities', [])
            for item in records:
                cve = item['cve']
                description = next((d['value'] for d in cve.get('descriptions', []) if d.get('lang') == 'en'), None)
                yield row(project, 'NVD', cve['id'], None, description, metadata=project_metadata('NVD', cve))
            offset += len(records)
            if offset >= data.get('totalResults', 0) or not records:
                break
        start = stop + dt.timedelta(days=1)


def opencve(project, cutoff):
    cfg = PROJECTS[project]
    path = 'https://app.opencve.io/api/v2/vendors/' + cfg['vendor']
    if cfg['product']:
        path += '/products/' + cfg['product']
    path += '/cves'
    page = 1
    while True:
        data, _ = request(path + '?' + urlencode({'page': page}), 'OpenCVE')
        if not isinstance(data, dict) or 'results' not in data or 'next' not in data:
            raise RuntimeError('unexpected OpenCVE pagination response')
        for item in data['results']:
            published = item.get('created_at') or ''
            if published and published[:10] < cutoff:
                detail, _ = request('https://app.opencve.io/api/v2/cves/' + item['cve_id'] + '?include=references,nvd_cpe_configurations', 'OpenCVE')
                if detail.get('cve_id') != item['cve_id']:
                    raise RuntimeError('OpenCVE identity mismatch')
                yield row(project, 'OpenCVE', item['cve_id'], item.get('title'), item.get('description'), metadata=project_metadata('OpenCVE', detail))
        if not data['next']:
            break
        page += 1


def community(project, cutoff):
    if project != 'OpenClaw':
        return
    raw, _ = request('https://raw.githubusercontent.com/jgamblin/OpenClawCVEs/main/README.md', 'Community CSV')
    lines = raw.splitlines()
    for index in range(len(lines) - 1):
        if not lines[index].strip().startswith('|') or not lines[index + 1].strip().startswith('|'):
            continue
        headers = [c.strip().lower() for c in lines[index].strip().strip('|').split('|')]
        divider = [c.strip() for c in lines[index + 1].strip().strip('|').split('|')]
        if not divider or not all(re.fullmatch(r':?-{3,}:?', c.replace(' ', '')) for c in divider):
            continue
        for line in lines[index + 2:]:
            if not line.strip().startswith('|'):
                break
            cells = [c.strip() for c in line.strip().strip('|').split('|')]
            if len(cells) != len(headers):
                continue
            values = dict(zip(headers, cells))
            match = re.search(r'CVE-\d{4}-\d{4,7}', line)
            if not match:
                continue
            title = next((values[h] for h in headers if re.search(r'title|vulnerability|issue|name', h) and values[h] and 'CVE-' not in values[h]), '')
            if not title:
                title = max((v for h, v in values.items() if v and 'CVE-' not in v and not re.search(r'date|cvss|severity|cve|url|link', h)), key=len, default='')
            value = next((values[h] for h in headers if re.search(r'published|disclos|date', h) and values[h]), '')
            date = re.search(r'20\d{2}-\d{2}-\d{2}', value)
            published = date.group() if date else None
            if not published:
                for fmt in ('%m/%d/%Y', '%b %d, %Y', '%B %d, %Y', '%d %b %Y'):
                    try:
                        published = dt.datetime.strptime(value.strip(), fmt).date().isoformat()
                        break
                    except ValueError:
                        pass
            if title and published and published < cutoff:
                metadata = community_metadata(lines[index], line)
                yield row(project, 'Community CSV', match.group(), title, None, metadata=metadata)


def frozen(path, projects, sources):
    selected = collections.OrderedDict()
    with Path(path).open(encoding='utf-8') as f:
        for line in f:
            item = json.loads(line)
            key = (item['project'], item['source'], str(item['record_id']))
            if key[0] in projects and key[1] in sources:
                if key in selected:
                    raise RuntimeError('duplicate ID in frozen list: ' + str(key))
                selected[key] = item
    return selected


def export_metadata(input_path, output_path):
    records = collections.OrderedDict()
    with Path(input_path).open(encoding='utf-8') as source:
        for line in source:
            item = json.loads(line)
            key = (item['project'], item['source'], item['record_id'])
            values = records.setdefault(key, [])
            value = item.get('source_metadata')
            if value is not None and value not in values:
                values.append(value)
    with Path(output_path).open('x', encoding='utf-8') as output:
        for (project, source, identifier), values in records.items():
            output.write(json.dumps({'project': project, 'source': source, 'record_id': identifier,
                                     'source_metadata': values or None}, ensure_ascii=False) + '\n')


def fetch_one(key, frozen_item):
    project, source, identifier = key
    repo = PROJECTS[project]['repo']
    if source == 'GitHub Issues':
        if not re.fullmatch(r'\d+', identifier):
            raise RuntimeError('invalid frozen issue ID')
        item, _ = request('https://api.github.com/repos/' + repo + '/issues/' + identifier, source)
        if str(item.get('number')) != identifier or 'pull_request' in item:
            raise RuntimeError('issue identity does not match frozen ID')
        expected = frozen_item.get('comment_sha256')
        comments = issue_comments(repo, identifier, expected) if expected else expected
        metadata = project_metadata(source, item)
        metadata['linked_changes'] = issue_links(repo, identifier)
        return [row(project, source, identifier, item.get('title'), item.get('body'), comments, metadata)]
    if source == 'GHSA':
        if not re.fullmatch(r'GHSA-[A-Z0-9]{4}-[A-Z0-9]{4}-[A-Z0-9]{4}', identifier):
            raise RuntimeError('invalid frozen GHSA ID')
        try:
            item, _ = request('https://api.github.com/repos/' + repo + '/security-advisories/' + identifier, source)
        except RuntimeError as exc:
            if not str(exc).startswith('HTTP 404'):
                raise
            item, _ = request('https://api.github.com/advisories/' + identifier, source)
        if item.get('ghsa_id', '').upper() != identifier:
            raise RuntimeError('advisory identity does not match frozen ID')
        return [row(project, source, identifier, item.get('summary'), item.get('description'), metadata=project_metadata(source, item))]
    if not re.fullmatch(r'CVE-\d{4}-\d{4,7}', identifier):
        raise RuntimeError('invalid frozen CVE ID')
    if source == 'NVD':
        data, _ = request('https://services.nvd.nist.gov/rest/json/cves/2.0?' + urlencode({'cveId': identifier}), source)
        matches = [v['cve'] for v in data.get('vulnerabilities', []) if v.get('cve', {}).get('id') == identifier]
        if len(matches) != 1:
            raise RuntimeError('CVE not found or identity mismatch')
        description = next((d['value'] for d in matches[0].get('descriptions', []) if d.get('lang') == 'en'), None)
        return [row(project, source, identifier, None, description, metadata=project_metadata(source, matches[0]))]
    item, _ = request('https://app.opencve.io/api/v2/cves/' + identifier + '?include=references,nvd_cpe_configurations', source)
    if item.get('cve_id') != identifier:
        raise RuntimeError('CVE identity does not match frozen ID')
    return [row(project, source, identifier, item.get('title'), item.get('description'), metadata=project_metadata(source, item))]


def main():
    load_config()
    parser = argparse.ArgumentParser()
    parser.add_argument('mode', choices=('discover', 'frozen', 'plan'))
    parser.add_argument('--project', choices=(*PROJECTS, 'all'), default='all')
    parser.add_argument('--source', choices=(*SOURCES, 'all'), default='all')
    parser.add_argument('--cutoff', default='2026-10-01')
    parser.add_argument('--manifest', default=str(ROOT / '00_frozen_records.jsonl'))
    parser.add_argument('--output')
    parser.add_argument('--freeze-output')
    parser.add_argument('--metadata-output')
    args = parser.parse_args()
    dt.date.fromisoformat(args.cutoff)
    projects = list(PROJECTS) if args.project == 'all' else [args.project]
    sources = list(SOURCES) if args.source == 'all' else [args.source]
    selected = frozen(args.manifest, projects, sources) if args.mode != 'discover' else {}
    if args.mode == 'plan':
        print(json.dumps({'unique_records': len(selected), 'by_source': dict(collections.Counter(k[1] for k in selected))}, ensure_ascii=False))
        return
    if not args.output:
        parser.error('--output is required')
    if args.metadata_output:
        paths = [Path(p).resolve() for p in (args.output, args.freeze_output, args.metadata_output) if p]
        if len(paths) != len(set(paths)):
            parser.error('output paths must differ')
        if Path(args.metadata_output).exists():
            parser.error('--metadata-output already exists')
    if args.mode == 'discover':
        if not args.freeze_output:
            parser.error('--freeze-output is required for discover')
        if Path(args.output).resolve() == Path(args.freeze_output).resolve():
            parser.error('--output and --freeze-output must differ')
        if Path(args.freeze_output).exists():
            parser.error('--freeze-output already exists')
    methods = {'GHSA': advisories, 'GitHub Issues': issues, 'NVD': nvd, 'OpenCVE': opencve, 'Community CSV': community}
    with Path(args.output).open('x', encoding='utf-8') as out:
        if args.mode == 'discover':
            for project in projects:
                for source in sources:
                    for item in methods[source](project, args.cutoff):
                        out.write(json.dumps(item, ensure_ascii=False) + '\n')
        else:
            community_keys = {k for k in selected if k[1] == 'Community CSV'}
            community_rows = collections.defaultdict(list)
            if community_keys:
                for item in community('OpenClaw', '9999-12-31'):
                    key = (item['project'], item['source'], item['record_id'])
                    if key in community_keys:
                        community_rows[key].append(item)
            for key, frozen_item in selected.items():
                rows = community_rows.get(key, []) if key[1] == 'Community CSV' else fetch_one(key, frozen_item)
                if not rows:
                    print('not found: ' + ' / '.join(key), file=sys.stderr)
                for item in rows:
                    out.write(json.dumps(item, ensure_ascii=False) + '\n')
    if args.mode == 'discover':
        count = export(args.output, args.freeze_output)
        print('saved ' + args.output + ' and ' + args.freeze_output + ' (' + str(count) + ' unique records)')
    else:
        print('saved ' + args.output)
    if args.metadata_output:
        export_metadata(args.output, args.metadata_output)
        print('saved ' + args.metadata_output)


if __name__ == '__main__':
    try:
        main()
    except (RuntimeError, OSError, ValueError) as exc:
        print(str(exc), file=sys.stderr)
        sys.exit(1)
