"""Conservative evidence grouping for PDF presentation; stored attempts stay unchanged."""
from engine.scorer import SEVERITY_WEIGHT
from report.assessment import row_value


def group_findings(findings):
    groups = {}
    for item in findings:
        f = dict(item)
        verdict = row_value(f, 'verdict', '')
        response = ' '.join(row_value(f, 'raw_response', '').split())
        source = row_value(f, 'source', '')
        # Only Garak attempts in the same probe family with identical observed
        # replies are collapsed. Different objectives in other engines stay separate.
        identity = (row_value(f, 'module', '') or row_value(f, 'rule_id', '')) if source == 'garak' else row_value(f, 'rule_id', '')
        if verdict == 'ERROR':
            evidence = row_value(f, 'description', '')
        elif response:
            evidence = response
        else:
            evidence = ('missing-response', row_value(f, 'id', row_value(f, 'rule_id', '')))
        key = (source, identity, row_value(f, 'owasp', ''), verdict, evidence)
        if key not in groups:
            groups[key] = dict(representative=f, members=[], severity=row_value(f, 'severity', 'low'))
        group = groups[key]
        group['members'].append(f)
        severity = row_value(f, 'severity', 'low')
        if SEVERITY_WEIGHT.get(severity, 0) > SEVERITY_WEIGHT.get(group['severity'], 0):
            group['severity'] = severity
    return list(groups.values())


def score_rows(groups):
    return [dict(verdict=g['representative']['verdict'], severity=g['severity']) for g in groups]


def methodology(mode_label):
    methods = []
    if 'Garak' in mode_label:
        methods.append('Garak supplied probe prompts and heuristic detector scores. Where configured, AI cross-checking evaluated saved replies; detector hits and model confidence are not independent proof of impact.')
    if 'Static' in mode_label or mode_label == 'Offline':
        methods.append('Static YAML payloads were evaluated using configured rules and optional AI cross-checking.')
    if 'AI-Powered' in mode_label or 'Ai Powered' in mode_label:
        methods.append('AI-Powered generated adaptive prompts within the selected categories and generation budget.')
    if 'AI-PENTEST' in mode_label or 'Ai Pentest' in mode_label:
        methods.append('AI-PENTEST profiled public behavior, planned within selected categories and ran bounded adaptive branches with saved evidence.')
    if 'PyRIT' in mode_label:
        methods.append('PyRIT ran configured objectives; recorded coverage limitations describe any fallback or unverified conversation continuity.')
    if 'Crescendo' in mode_label:
        methods.append('Crescendo used multi-turn escalation and backtracking against configured objectives.')
    return ' '.join(methods) or 'This report describes the recorded engine results for the saved target profile; it does not assume how that profile was discovered.'
