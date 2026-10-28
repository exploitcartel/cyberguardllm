from unittest.mock import patch
from tests.base import CyberGuardTestCase
from core.avatars import AVATARS, resolve_avatar, validate_avatar


class RobotAvatarTests(CyberGuardTestCase):
    def test_ten_stable_target_identities_and_validated_names(self):
        values = [resolve_avatar(dict(id=n)) for n in range(1,11)]
        self.assertEqual(len(set(values)), 10)
        self.assertEqual(set(values), set(AVATARS))
        self.assertEqual(resolve_avatar(dict(id=1,avatar_variant='spectre')), 'spectre')
        with patch('core.avatars.secrets.choice', side_effect=lambda choices: choices[0]) as choose:
            selected=resolve_avatar(dict(id=1,avatar_random=1),previous='android')
            self.assertNotEqual(selected,'android')
            self.assertNotIn('android',choose.call_args.args[0])
        with self.assertRaises(ValueError):validate_avatar('../unknown')

    def test_target_edit_saves_choices_and_rejects_invalid_input(self):
        self.client.post('/targets/save',data=dict(name='fixture',url='http://unused',token='',auth_scheme='none',body_format='message',response_field='reply',avatar_variant='cyclops',avatar_random='on'))
        c=self.get_conn()
        try:
            target=c.execute('SELECT * FROM targets').fetchone()
            self.assertEqual((target['avatar_variant'],target['avatar_random']),('cyclops',1))
            form=dict(name='fixture',url='http://unused',auth_scheme='none',body_format='message',response_field='reply',avatar_variant='oracle')
            self.assertEqual(self.client.post('/targets/1/edit',data=form).status_code,302)
            self.assertEqual(c.execute('SELECT avatar_variant,avatar_random FROM targets').fetchone()[:],('oracle',0))
            self.assertEqual(self.client.post('/targets/1/edit',data=dict(form,avatar_variant='invalid')).status_code,400)
        finally:c.close()

    def test_random_selection_is_saved_once_per_scan_and_survives_target_edit(self):
        from engine import runner
        c=self.get_conn()
        c.execute("INSERT INTO targets(name,url,token_encrypted,avatar_random) VALUES ('fixture','http://unused','',1)")
        c.execute("INSERT INTO scan_configs(name,enable_static,ai_powered,use_ai_pentest,categories) VALUES ('no requests',0,0,0,'')")
        c.execute("INSERT INTO tasks(target_id,scan_config_id,status) VALUES (1,1,'pending')")
        c.commit()
        with patch('core.avatars.secrets.choice',return_value='sentient') as choose:
            runner._execute(1)
        self.assertEqual(choose.call_count,1)
        self.assertEqual(c.execute('SELECT avatar_variant FROM scan_results').fetchone()[0],'sentient')
        c.execute("UPDATE targets SET avatar_variant='facet',avatar_random=0 WHERE id=1")
        c.commit()
        page=self.client.get('/scan/1/live').get_data(as_text=True)
        self.assertIn('variant: "sentient"',page)
        self.assertEqual(self.client.get('/api/scan-status/1').get_json()['avatar_variant'],'sentient')
        c.close()

    def test_catalog_and_geometry_module_are_available(self):
        page=self.client.get('/avatars').get_data(as_text=True)
        self.assertEqual(page.count('data-avatar='),10)
        for key in AVATARS:self.assertIn(f'data-avatar="{key}"',page)
        response=self.client.get('/static/js/robot-avatars.js')
        self.assertIn(b'buildRobotAvatar',response.data)
        response.close()
