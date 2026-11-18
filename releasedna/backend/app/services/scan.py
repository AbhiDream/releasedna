import time
import uuid
from datetime import datetime, timezone
import httpx
from app.core.safety import Fetcher, InspectionError, inspect_archive
from app.connectors.registry import fetch_release, validate_input
from app.source_resolver.resolve import resolve
from app.diff_engine.compare import compare, CLEAN_MEANING


def scan(ecosystem, name, version):
    validate_input(ecosystem, name, version)
    started = time.monotonic()
    result = {'scan_id': str(uuid.uuid4()), 'created_at': datetime.now(timezone.utc).isoformat(),
              'package': {'ecosystem': ecosystem, 'name': name, 'version': version},
              'status': 'INCONCLUSIVE', 'risk_score': None, 'risk_reasons': {},
              'publication': None, 'artifact': None, 'repository': None, 'source': None,
              'total_files_inspected': 0, 'counts': {}, 'findings': [], 'files': [],
              'limitations': [], 'engine_version': '0.1.1', 'error': None, 'clean_definition': CLEAN_MEANING,
              'metrics': {'artifact_file_count': 0, 'source_file_count': 0, 'unique_comparison_paths': 0,
                          'identical_files': 0, 'added_files': 0, 'removed_files': 0, 'changed_files': 0}}
    fetcher = Fetcher()
    try:
        release, blob = fetch_release(fetcher, ecosystem, name, version)
        result.update({key: release[key] for key in ('publication', 'artifact', 'repository')})
        artifact = inspect_archive(blob)
        try:
            source_info, source = resolve(fetcher, release)
        except (InspectionError, httpx.HTTPError, ValueError, KeyError, TypeError, AttributeError, RecursionError) as exc:
            source_info, source = {'identity_corroborated': False, 'build_provenance_verified': False,
                                   'confidence': 'unresolved', 'reasons': [str(exc)]}, {}
        result['source'] = source_info
        result.update(compare(artifact, source, source_info['identity_corroborated']))
        result['limitations'].extend([
            'Static heuristic analysis cannot certify that a package is malware-free.',
            'Builds are never executed; compiled output and complex source layouts may remain unexplained.',
            'Source matching corroborates registry and repository claims; attestations are not verified.',
            'Phase 1 supports npm tarballs and PyPI source distributions, with GitHub source repositories.',
        ])
    except (InspectionError, httpx.HTTPError, ValueError, KeyError, TypeError, AttributeError, RecursionError) as exc:
        result['error'] = f'{type(exc).__name__}: {exc}'
        result['limitations'].append(f'Inspection could not complete: {type(exc).__name__}: {exc}')
    finally:
        fetcher.close()
    result['duration_seconds'] = round(time.monotonic() - started, 3)
    return result
