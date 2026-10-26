"""Updater tests use an isolated repository, database and fake server processes."""
import os
from pathlib import Path
import sqlite3
import tempfile
import unittest
from unittest.mock import patch, Mock

from core import updates
from integrations import update_worker
from tests.base import CyberGuardTestCase


class UpdateRepositoryTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        self.patches = [patch.object(updates, 'ROOT', self.root),
                        patch.object(updates, 'STATE_DIR', self.root / '.runtime' / 'updates'),
                        patch.dict(os.environ, CGLLM_MANAGED_LOCAL='1', CGLLM_DEBUG='0')]
        for item in self.patches: item.start()
        updates.git('init', '-b', 'main')
        updates.git('config', 'user.name', 'exploitcartel')
        updates.git('config', 'user.email', 'exploitcartel@gmail.com')
        (self.root / '.gitignore').write_text('.runtime/\n*.db\n*.key\n', encoding='utf-8')
        (self.root / 'run.py').write_text('print("old")\n', encoding='utf-8')
        updates.git('add', '.')
        updates.git('commit', '-m', 'Initial fixture')
        self.previous = updates.git('rev-parse', 'HEAD')
        (self.root / 'run.py').write_text('print("new")\n', encoding='utf-8')
        updates.git('add', '.')
        updates.git('commit', '-m', 'New fixture')
        self.target = updates.git('rev-parse', 'HEAD')
        updates.git('update-ref', 'refs/remotes/origin/main', self.target)
        updates.git('reset', '--hard', self.previous)
        updates.git('remote', 'add', 'origin', updates.SOURCE + '.git')
        self.conn = sqlite3.connect(self.root / 'app.db')
        self.conn.execute('CREATE TABLE tasks (status TEXT)')
        self.conn.commit()
        real_git = updates.git
        self.fetch = patch.object(updates, 'git', side_effect=lambda *args, **kw:
                                 '' if args[0] == 'fetch' else real_git(*args, **kw))
        self.fetch.start()
        updates.check_updates()

    def tearDown(self):
        self.fetch.stop()
        self.conn.close()
        for item in reversed(self.patches): item.stop()
        self.temporary.cleanup()

    def test_check_previews_commits_without_changing_checkout(self):
        view = updates.status(self.conn)
        self.assertTrue(view['can_install'], view['blockers'])
        self.assertEqual(view['check']['behind'], 1)
        self.assertEqual(view['check']['commits'][0]['title'], 'New fixture')
        self.assertEqual(updates.git('rev-parse', 'HEAD'), self.previous)

    def test_active_scan_dirty_checkout_dependencies_and_unmanaged_block_install(self):
        self.conn.execute("INSERT INTO tasks VALUES ('running')")
        self.conn.commit()
        self.assertFalse(updates.status(self.conn)['can_install'])
        self.conn.execute('DELETE FROM tasks')
        self.conn.commit()
        (self.root / 'uncommitted.txt').write_text('local change')
        self.assertFalse(updates.status(self.conn)['can_install'])
        (self.root / 'uncommitted.txt').unlink()
        check = updates.read_json(updates.STATE_DIR / 'check.json')
        updates.write_json(updates.STATE_DIR / 'check.json', dict(check, dependency_changes=True))
        self.assertFalse(updates.status(self.conn)['can_install'])
        updates.write_json(updates.STATE_DIR / 'check.json', check)
        with patch.dict(os.environ, CGLLM_MANAGED_LOCAL='0'):
            self.assertFalse(updates.status(self.conn)['can_install'])

    def test_origin_allowlist(self):
        for url in [updates.SOURCE, updates.SOURCE + '.git', 'git@github.com:exploitcartel/cyberguardllm.git']:
            self.assertTrue(updates.trusted_origin(url))
        for url in ['https://github.com/attacker/cyberguardllm', 'https://github.com.evil/ exploitcartel/cyberguardllm',
                    'https://user:secret@github.com/exploitcartel/cyberguardllm', 'https://[broken', 'ext::command']:
            self.assertFalse(updates.trusted_origin(url))

    def test_failed_network_check_never_claims_up_to_date(self):
        with patch.object(updates, 'git', side_effect=updates.UpdateError('Network unavailable')):
            check = updates.check_updates()
        self.assertIn('Network unavailable', check['error'])
        self.assertNotIn('latest', check)
        self.assertFalse(updates.status(self.conn)['can_install'])

    def test_unchecked_commit_rejected_and_worker_launch_failure_keeps_server(self):
        with self.assertRaises(updates.UpdateError):
            updates.start_install(self.conn, self.previous)
        with patch.object(updates, 'spawn_worker', side_effect=OSError('launch error')):
            with self.assertRaises(updates.UpdateError):
                updates.start_install(self.conn, self.target)
        self.assertEqual(updates.job_status()['status'], 'error')
        self.assertEqual(updates.git('rev-parse', 'HEAD'), self.previous)

    def test_backup_restart_and_rollback_restore_data(self):
        self.conn.execute("INSERT INTO tasks VALUES ('completed')")
        self.conn.commit()
        with patch.object(updates, 'spawn_worker'):
            updates.start_install(self.conn, self.target)
        self.conn.close()
        self.conn = sqlite3.connect(self.root / 'app.db')
        def fake_launch(job, log):
            db = sqlite3.connect(job['database'])
            db.execute("UPDATE tasks SET status='changed-by-migration'")
            db.commit()
            db.close()
            return Mock()
        # First launch simulates a failed migration/startup; old launch leaves restored data alone.
        with patch.object(update_worker, 'port_open', return_value=False), \
             patch.object(update_worker, 'launch', side_effect=[fake_launch_stub := Mock(), Mock()]), \
             patch.object(update_worker, 'healthy', side_effect=[False, True]), \
             patch.object(update_worker, 'terminate_owned'):
            # Change the database as a failed new server would, after backup has completed.
            original_healthy = update_worker.healthy
            def check(process, port):
                if process is fake_launch_stub:
                    fake_launch(updates.read_json(updates.STATE_DIR / 'job.json'), None)
                return original_healthy(process, port)
            with patch.object(update_worker, 'healthy', side_effect=check):
                update_worker.run(updates.STATE_DIR / 'job.json')
        self.assertEqual(updates.git('rev-parse', 'HEAD'), self.previous)
        self.assertEqual(self.conn.execute('SELECT status FROM tasks').fetchone()[0], 'completed')
        self.assertEqual(updates.job_status()['status'], 'error')
        self.assertIn('Previous version is running', updates.job_status()['error'])
        self.assertTrue((updates.STATE_DIR / 'backups' / updates.job_status()['backup'] / 'database.db').is_file())

    def test_successful_worker_updates_checkpoint(self):
        with patch.object(updates, 'spawn_worker'):
            updates.start_install(self.conn, self.target)
        with patch.object(update_worker, 'port_open', return_value=False), \
             patch.object(update_worker, 'launch', return_value=Mock()), \
             patch.object(update_worker, 'healthy', return_value=True):
            update_worker.run(updates.STATE_DIR / 'job.json')
        self.assertEqual(updates.git('rev-parse', 'HEAD'), self.target)
        self.assertEqual(updates.job_status()['status'], 'completed')
        self.assertFalse(updates.status(self.conn)['can_install'])


class UpdateAndProviderPageTests(CyberGuardTestCase):
    def setUp(self):
        super().setUp()
        self.runtime = tempfile.TemporaryDirectory()
        self.state_patch = patch.object(updates, 'STATE_DIR', Path(self.runtime.name))
        self.state_patch.start()

    def tearDown(self):
        self.state_patch.stop()
        self.runtime.cleanup()
        super().tearDown()

    def test_update_page_has_sidebar_and_never_fetches_on_get(self):
        with patch.object(updates, 'check_updates') as fetch:
            page = self.client.get('/updates')
        self.assertEqual(page.status_code, 200)
        self.assertIn(b'href="/updates"', page.data)
        fetch.assert_not_called()

    def test_update_actions_are_global_admin_only(self):
        with patch.object(self.app_mod, 'role_at_least', return_value=False), \
             patch.object(updates, 'check_updates') as fetch, patch.object(updates, 'start_install') as install:
            self.assertEqual(self.client.post('/updates/check').status_code, 403)
            self.assertEqual(self.client.post('/updates/install').status_code, 403)
        fetch.assert_not_called()
        install.assert_not_called()

    def test_installation_blocks_scan_creation_and_keeps_status_page_available(self):
        updates.write_json(updates.STATE_DIR / 'job.json', dict(status='installing', updated_at=__import__('time').time()))
        self.assertEqual(self.client.post('/tasks/run', data={'target_id': '1', 'config_id': '1'}).status_code, 503)
        self.assertEqual(self.client.get('/api/update-status').status_code, 200)
        conn = self.get_conn()
        self.assertEqual(conn.execute('SELECT COUNT(*) FROM tasks').fetchone()[0], 0)
        conn.close()

    def test_presets_render_and_other_endpoint_needs_model_and_replacement_key(self):
        from storage.db import get_setting, set_setting
        page = self.client.get('/settings?tab=scan')
        for label in (b'OpenRouter', b'Groq', b'DeepSeek'):
            self.assertIn(label, page.data)
        set_setting('ai_api_base', 'https://api.openai.com/v1')
        set_setting('ai_api_key_encrypted', 'encrypted-fixture')
        data = {'ai_provider': 'openai_compatible', 'ai_api_base': 'https://api.groq.com/openai/v1', 'ai_model': 'account-model'}
        self.client.post('/settings/scan-mode', data=data)
        self.assertEqual(get_setting('ai_api_base'), 'https://api.openai.com/v1')
        self.client.post('/settings/scan-mode', data=dict(data, ai_api_key='new-test-key', ai_model=''))
        self.assertEqual(get_setting('ai_api_base'), 'https://api.openai.com/v1')
        self.client.post('/settings/scan-mode', data=dict(data, ai_api_key='new-test-key'))
        self.assertEqual(get_setting('ai_api_base'), data['ai_api_base'])
        self.assertEqual(get_setting('ai_provider'), 'openai_compatible')

    def test_compatible_presets_use_the_selected_endpoint_and_bearer_key(self):
        from engine.ai_agent import ENDPOINT_PRESETS, _chat_openai_compatible
        response = Mock()
        response.json.return_value = {'choices': [{'message': {'content': 'fixture reply'}, 'finish_reason': 'stop'}]}
        for preset in ENDPOINT_PRESETS.values():
            with self.subTest(provider=preset['label']), patch('engine.ai_agent.requests.post', return_value=response) as post:
                result = _chat_openai_compatible(preset['api_base'], 'fixture-key', 'account-model', 's', 'u', 10)
                self.assertEqual(result, 'fixture reply')
                args, kwargs = post.call_args
                self.assertEqual(args[0], preset['api_base'] + '/chat/completions')
                self.assertEqual(kwargs['headers']['Authorization'], 'Bearer fixture-key')
                self.assertEqual(kwargs['json']['model'], 'account-model')

