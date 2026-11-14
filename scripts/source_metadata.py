import re


def present(value):
    return value if value not in (None, '', [], {}) else None


def project_metadata(source, record):
    if source == 'GHSA':
        keys = ('identifiers', 'cve_id', 'ghsa_id', 'severity', 'cvss', 'cvss_severities', 'cwes', 'cwe_ids', 'vulnerabilities', 'references', 'html_url', 'source_code_location', 'repository_advisory_url', 'published_at', 'updated_at', 'withdrawn_at')
    elif source == 'NVD':
        keys = ('id', 'sourceIdentifier', 'published', 'lastModified', 'vulnStatus', 'metrics', 'weaknesses', 'affected', 'configurations', 'references')
    elif source == 'OpenCVE':
        keys = ('cve_id', 'created_at', 'updated_at', 'metrics', 'weaknesses', 'vendors', 'references', 'nvd_cpe_configurations')
    elif source == 'GitHub Issues':
        keys = ('html_url', 'labels', 'state', 'state_reason', 'created_at', 'updated_at', 'closed_at')
    elif source == 'Community CSV':
        keys = ('cve', 'severity', 'cvss', 'cwe', 'published')
    else:
        raise ValueError('unsupported source')
    result = {key: present(record.get(key)) for key in keys}
    if source == 'GitHub Issues' and result['labels'] is not None:
        result['labels'] = [label.get('name') for label in result['labels'] if isinstance(label, dict) and label.get('name')]
    return result


def community_metadata(header, line):
    headers = [x.strip().lower() for x in header.strip().strip('|').split('|')]
    cells = [x.strip() for x in line.strip().strip('|').split('|')]
    if len(headers) != len(cells):
        return None
    values = dict(zip(headers, cells))
    fields = {}
    for name, pattern in [('cve', r'^cve(?:\s*id)?$'), ('severity', r'severity'), ('cvss', r'cvss'), ('cwe', r'cwe'), ('published', r'publish|disclos|date')]:
        fields[name] = next((values[h] for h in headers if re.search(pattern, h)), None)
    return project_metadata('Community CSV', fields)
