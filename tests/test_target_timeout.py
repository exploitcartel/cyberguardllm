import json
import threading
import time
import unittest
from http.server import BaseHTTPRequestHandler,ThreadingHTTPServer
from unittest.mock import patch,Mock

from core import discovery
from core.transport_policy import response_timeout,http_timeout
from tests.base import CyberGuardTestCase


class TimeoutTransportTests(unittest.TestCase):
    def setUp(self):
        settings=patch('storage.db.get_setting',side_effect=lambda key,default=None:default)
        settings.start()
        self.addCleanup(settings.stop)

    def target(self,**extra):
        return dict(url='http://unused/chat',auth_scheme='none',token_encrypted='',body_format='message',
                    response_field='reply',body_encoding='json',transport='http',**extra)

    def test_configured_timeout_wins_for_single_and_multi_turn_http(self):
        response=Mock(status_code=200,headers={'Content-Type':'application/json'})
        response.text=json.dumps({'reply':'fixture reply'})
        response.json.return_value={'reply':'fixture reply'}
        target=self.target(request_timeout=240)
        with patch('core.crypto.decrypt_token',return_value=''), patch('core.discovery.requests.post',return_value=response) as post:
            self.assertEqual(discovery.send_prompt(target,'fixture',timeout=45),'fixture reply')
            self.assertEqual(post.call_args.kwargs['timeout'],(10,240))
            target['body_format']='messages'
            reply,history=discovery.send_conversation_turn(target,'fixture',[],timeout=20)
            self.assertEqual(reply,'fixture reply')
            self.assertEqual(post.call_args.kwargs['timeout'],(10,240))

    def test_ws_socketio_share_the_target_budget_and_do_not_fake_http_history(self):
        target=self.target(request_timeout=240)
        target.update(transport='ws',body_format='messages')
        with patch('core.ws_discovery.send_prompt_ws',return_value='fixture reply') as send:
            reply,_=discovery.send_conversation_turn(target,'fixture',[],timeout=20)
        self.assertEqual(reply,'fixture reply')
        self.assertEqual(send.call_args.kwargs['timeout'],240)
        target['transport']='socketio'
        with patch('core.socketio_discovery.send_prompt_socketio',return_value='fixture reply') as send:
            discovery.send_prompt(target,'fixture',timeout=45)
        self.assertEqual(send.call_args.kwargs['timeout'],240)

    def test_policy_clamps_bad_values_and_separates_connect_from_read(self):
        self.assertEqual(http_timeout({'request_timeout':300},45),(10,300))
        self.assertEqual(response_timeout({'request_timeout':float('nan')},45),180)
        self.assertEqual(response_timeout({'request_timeout':900},45),600)
        self.assertEqual(response_timeout({},45),45)

    def test_slow_fixture_succeeds_with_profile_budget_without_duplicate_replays(self):
        calls=[]
        class Handler(BaseHTTPRequestHandler):
            def do_POST(self):
                calls.append(self.rfile.read(int(self.headers['Content-Length'])))
                time.sleep(.2)
                body=json.dumps({'reply':'Slow fixture answer'}).encode()
                self.send_response(200);self.send_header('Content-Type','application/json');self.send_header('Content-Length',str(len(body)));self.end_headers()
                try:self.wfile.write(body)
                except (BrokenPipeError,ConnectionResetError,ConnectionAbortedError):pass
            def log_message(self,*args):pass
        server=ThreadingHTTPServer(('127.0.0.1',0),Handler)
        threading.Thread(target=server.serve_forever,daemon=True).start()
        try:
            target=self.target();target['url']=f'http://127.0.0.1:{server.server_port}/chat'
            with patch('core.crypto.decrypt_token',return_value=''),patch('core.discovery.get_proxies',return_value={}):
                failed=discovery.send_prompt(target,'fixture',timeout=.05,max_retries=2)
                self.assertTrue(failed.startswith('[ERROR]'))
                target['request_timeout']=5
                self.assertEqual(discovery.send_prompt(target,'fixture',timeout=.05,max_retries=2),'Slow fixture answer')
            self.assertEqual(len(calls),2)
        finally:
            server.shutdown();server.server_close()


class TimeoutTargetPageTests(CyberGuardTestCase):
    def test_new_edit_and_validation_preserve_credentials(self):
        data=dict(name='fixture',url='http://unused',auth_scheme='none',body_format='message',response_field='reply',request_timeout='240')
        self.assertEqual(self.client.post('/targets/save',data=data).status_code,302)
        conn=self.get_conn()
        try:
            row=conn.execute('SELECT * FROM targets').fetchone()
            self.assertEqual(row['request_timeout'],240)
            secret=row['token_encrypted']
            self.assertIn('name="request_timeout"',self.client.get('/targets/1/edit').get_data(as_text=True))
            self.assertEqual(self.client.post('/targets/1/edit',data=dict(data,request_timeout='300')).status_code,302)
            row=conn.execute('SELECT * FROM targets').fetchone()
            self.assertEqual((row['request_timeout'],row['token_encrypted']),(300,secret))
            self.assertEqual(self.client.post('/targets/1/edit',data=dict(data,request_timeout='9999')).status_code,400)
            self.assertEqual(conn.execute('SELECT request_timeout FROM targets').fetchone()[0],300)
        finally:conn.close()

    def test_http_discovery_preserves_timeout_in_save_form(self):
        result=dict(status='success',auth_scheme='none',body_format='message',body_encoding='json',response_field='reply',sample_response='fixture')
        with patch.object(self.app_mod,'discover_target',return_value=result) as discover:
            page=self.client.post('/targets/discover',data=dict(name='fixture',url='http://unused',request_timeout='240'))
        self.assertEqual(discover.call_args.kwargs['timeout'],240)
        self.assertIn('value="240"',page.get_data(as_text=True))
