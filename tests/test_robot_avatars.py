from unittest.mock import patch
from tests.base import CyberGuardTestCase
from core.avatars import AVATARS, resolve_avatar, validate_avatar, ensure_avatar, migrate_identities


class RobotAvatarTests(CyberGuardTestCase):
    def form(self):
        return dict(name='fixture',url='http://unused/chat',token='',auth_scheme='none',body_format='message',response_field='reply')

    def test_eleven_identities_include_original_and_resolution_never_randomizes(self):
        self.assertEqual(len(AVATARS),11)
        self.assertIn('legacy',AVATARS)
        self.assertEqual(set(resolve_avatar(dict(id=n)) for n in range(1,12)),set(AVATARS))
        with patch('core.avatars.secrets.choice') as choose:
            for _ in range(3):
                self.assertEqual(resolve_avatar(dict(id=1,avatar_variant='legacy',avatar_random=1)),'legacy')
        choose.assert_not_called()
        with self.assertRaises(ValueError):validate_avatar('../unknown')

    def test_identity_assigned_once_and_immutable_on_edit(self):
        with patch('core.avatars.secrets.choice',return_value='legacy') as choose:
            self.assertEqual(self.client.post('/targets/save',data=self.form()).status_code,302)
        choose.assert_called_once()
        c=self.get_conn()
        self.addCleanup(c.close)
        self.assertEqual(c.execute('SELECT avatar_variant,avatar_random FROM targets').fetchone()[:],('legacy',0))
        form=dict(self.form(),avatar_variant='oracle',avatar_random='on')
        self.assertEqual(self.client.post('/targets/1/edit',data=form).status_code,302)
        self.assertEqual(c.execute('SELECT avatar_variant,avatar_random FROM targets').fetchone()[:],('legacy',0))

    def test_delete_and_readd_same_endpoint_excludes_previous_identity(self):
        with patch('core.avatars.secrets.choice',side_effect=lambda options: options[0]):
            self.client.post('/targets/save',data=self.form())
        c=self.get_conn();self.addCleanup(c.close)
        old=c.execute('SELECT id,avatar_variant FROM targets').fetchone()
        response=self.client.post(f'/targets/{old["id"]}/delete')
        self.assertEqual(response.status_code,302)
        with patch('core.avatars.secrets.choice',side_effect=lambda options: options[0]) as choose:
            self.client.post('/targets/save',data=self.form())
        self.assertNotIn(old['avatar_variant'],choose.call_args.args[0])
        self.assertNotEqual(c.execute('SELECT avatar_variant FROM targets').fetchone()[0],old['avatar_variant'])
        self.assertEqual(c.execute('SELECT COUNT(*) FROM target_avatar_history').fetchone()[0],1)

    def test_all_scans_keep_same_human_identity_and_saved_snapshot(self):
        from engine import runner
        c=self.get_conn();self.addCleanup(c.close)
        with patch('core.avatars.secrets.choice',return_value='legacy'):
            self.client.post('/targets/save',data=self.form())
        c.execute("INSERT INTO scan_configs(name,enable_static,ai_powered,use_ai_pentest,categories) VALUES ('no requests',0,0,0,'')")
        c.executemany("INSERT INTO tasks(target_id,scan_config_id,status) VALUES (1,1,'pending')",[(),()]);c.commit()
        with patch('core.avatars.secrets.choice') as choose:
            runner._execute(1);runner._execute(2)
        choose.assert_not_called()
        self.assertEqual([r[0] for r in c.execute('SELECT avatar_variant FROM scan_results ORDER BY id')],['legacy','legacy'])
        page=self.client.get('/scan/2/live').get_data(as_text=True)
        self.assertIn('variant: "legacy"',page)
        self.assertEqual(self.client.get('/api/scan-status/2').get_json()['avatar_variant'],'legacy')
        c.execute("UPDATE targets SET avatar_variant='facet' WHERE id=1");c.commit()
        self.assertEqual(self.client.get('/api/scan-status/2').get_json()['avatar_variant'],'legacy')

    def test_migration_freezes_last_scan_and_is_idempotent(self):
        c=self.get_conn();self.addCleanup(c.close)
        c.execute("INSERT INTO targets(name,url,token_encrypted,avatar_random) VALUES ('fixture','http://unused','',1)")
        c.execute("INSERT INTO scan_results(target_id,avatar_variant) VALUES (1,'cyclops')");c.commit()
        migrate_identities(c)
        self.assertEqual(c.execute('SELECT avatar_variant,avatar_random FROM targets').fetchone()[:],('cyclops',0))
        self.assertEqual(c.execute('SELECT avatar_variant FROM scan_results').fetchone()[0],'cyclops')
        with patch('core.avatars.secrets.choice') as choose:migrate_identities(c)
        choose.assert_not_called()
        self.assertEqual(c.execute('SELECT avatar_variant FROM targets').fetchone()[0],'cyclops')

    def test_catalog_includes_human_and_creation_has_no_per_scan_random_switch(self):
        page=self.client.get('/avatars').get_data(as_text=True)
        self.assertEqual(page.count('data-avatar='),11)
        self.assertIn('data-avatar="legacy"',page)
        page=self.client.get('/targets/new').get_data(as_text=True)
        self.assertNotIn('name="avatar_random"',page)
        response=self.client.get('/static/js/robot-avatars.js')
        self.assertIn(b'buildRobotAvatar',response.data);response.close()
