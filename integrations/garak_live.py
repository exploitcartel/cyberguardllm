"""Small runtime hooks for garak 0.17: announce the actual plan and score each attempt before the next request.
No installed garak source files are modified.
"""
import json
import os
import time
import types


class ScanStopped(Exception):
    pass


def emit(kind, **values):
    path = os.environ.get('CGLLM_GARAK_EVENTS')
    if path:
        with open(path, 'a', encoding='utf-8') as f:
            f.write(json.dumps({'kind': kind, **values}, ensure_ascii=False) + '\n')
            f.flush()


def check_control():
    task_id = os.environ.get('CGLLM_GARAK_TASK')
    if not task_id:
        return
    import storage.db as db
    if os.environ.get('CGLLM_GARAK_DB'):
        db.DB_PATH = os.environ['CGLLM_GARAK_DB']
    while True:
        c = db.get_conn()
        try:
            row = c.execute('SELECT control FROM tasks WHERE id=?', (task_id,)).fetchone()
        finally:
            c.close()
        if row and row[0] == 'stop':
            raise ScanStopped()
        if not row or row[0] != 'pause':
            return
        time.sleep(.2)


def install():
    from garak import _plugins, _config
    from garak.harnesses.base import Harness
    from garak.harnesses.probewise import ProbewiseHarness
    old_queue = ProbewiseHarness.run
    old_run = Harness.run
    old_detector = Harness._run_detector

    def plan(self, model, probenames, evaluator, buff_names=None):
        # Use the same config and cached probe instances that the harness will execute.
        planned = []
        for name in sorted(probenames):
            check_control()
            probe = _plugins.load_plugin(name)
            if probe:
                planned.append({'probe': name, 'prompts': len(getattr(probe, 'prompts', [])),
                                'generations': getattr(probe, 'generations', 1)})
        emit('plan', total=sum(p['prompts'] * p['generations'] for p in planned), probes=planned)
        return old_queue(self, model, probenames, evaluator, buff_names)

    def score(self, attempts, detector):
        # The main harness sees scores already computed by live_run; do not invoke a detector twice.
        key = detector.detectorname.replace('garak.detectors.', '')
        missing = [a for a in attempts if key not in a.detector_results]
        if missing:
            return old_detector(self, missing, detector)

    def live_run(self, model, probes, detectors, evaluator, announce_probe=True):
        originals = []
        for probe in probes:
            original = probe._execute_all
            originals.append((probe, original))

            def execute(p, attempts, original=original):
                completed = []
                for attempt in attempts:
                    check_control()
                    results = original([attempt])
                    for detector in detectors:
                        score(self, results, detector)
                    for result in results:
                        result.status = 2
                        record = result.as_dict()
                        emit('attempt', record=record)
                        _config.transient.reportfile.write(json.dumps(record, ensure_ascii=False) + '\n')
                        _config.transient.reportfile.flush()
                    completed.extend(results)
                return completed

            probe._execute_all = types.MethodType(execute, probe)
        try:
            return old_run(self, model, probes, detectors, evaluator, announce_probe)
        finally:
            for probe, original in originals:
                probe._execute_all = original

    ProbewiseHarness.run = plan
    Harness.run = live_run
    Harness._run_detector = score
