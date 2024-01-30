import html
import math
import traceback
from types import TracebackType
from typing import Type
from flask import Flask, make_response, render_template, request, redirect, session
import json
import mastodon
from misskey import Misskey, MiAuth, Permissions
from misskey.exceptions import *
import random
from datetime import timedelta
import urllib.parse
import sqlite3
import re
import MeCab
import markovify
import config
import requests
import uuid
import hashlib
import re
import threading
import time
import Levenshtein as levsh
import sentry_sdk
from sentry_sdk.integrations.flask import FlaskIntegration

def format_bytes(size):
    power = 2 ** 10  # 2**10 = 1024
    n = 0
    power_labels = ['B', 'KB', 'MB', 'GB', 'TB']
    while size > power and n <= len(power_labels):
        size /= power
        n += 1
    return '{:.0f} {}'.format(size, power_labels[n])

def proc_error_hook(args):
    print(''.join(traceback.format_exception(args.exc_type, args.exc_value, args.exc_traceback)))
    job_status[args.thread.name] = {
        'completed': True,
        'error': f'スレッドが異常終了しました<br><strong>{args.exc_type.__name__}</strong><div>{str(args.exc_value)}</div>'
    }

threading.excepthook = proc_error_hook

def dict_factory(cursor, row):
   d = {}
   for idx, col in enumerate(cursor.description):
       d[col[0]] = row[idx]
   return d

def format_text(t):
    t = t.replace('　', ' ')  # Full width spaces
    # t = re.sub(r'([。．！？…]+)', r'\1\n', t)  # \n after ！？
    t = re.sub(r'(.+。) (.+。)', r'\1 \2\n', t)
    t = re.sub(r'\n +', '\n', t)  # Spaces
    t = re.sub(r'([。．！？…])\n」', r'\1」 \n', t)  # \n before 」
    t = re.sub(r'\n +', '\n', t)  # Spaces
    t = re.sub(r'\n+', r'\n', t).rstrip('\n')  # Empty lines
    t = re.sub(r'\n +', '\n', t)  # Spaces
    t = re.sub(r'(http|ftp|https):\/\/[\w\-_]+(\.[\w\-_]+)+([\w\-\.,@?^=%&amp;:/~\+#]*[\w\-\@?^=%&amp;/~\+#])?', '', t) # URL
    return t

def create_markov_model_by_multiline(lines: list):
    # MeCabで形態素解析
    parsed_text = []
    mecab_options = ['-Owakati']
    try:
        if getattr(config, 'MECAB_DICDIR'):
            mecab_options.append(f'-d{config.MECAB_DICDIR}')
    except:
        pass

    try:
        if getattr(config, 'MECAB_RC'):
            mecab_options.append(f'-r{config.MECAB_RC}')
    except:
        pass
    
    for line in lines:
        parsed_text.append(MeCab.Tagger(' '.join(mecab_options)).parse(line))
    
    # モデル作成
    try:
        text_model = markovify.NewlineText('\n'.join(parsed_text), state_size=2)
    except:
        raise Exception('<meta name="viewport" content="width=device-width">モデル作成に失敗しました。学習に必要な投稿数が不足している可能性があります。', 500)

    return text_model

USER_AGENT = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64; Markov-Generator-Fedi) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36'

db = sqlite3.connect('markov.db', check_same_thread=False)
db.row_factory = dict_factory

# job_statusの使い方
# {
#   'completed': bool[True, False], # ジョブが停止したかどうか
#   'error': Optional[str], # エラーが発生した場合のエラーメッセージ (エラーない時はNoneにする)
#   'progress': int, # 完了率 (0-100、任意)
#   'result': Optional[str] # 完了した時のメッセージ (完了していない時はNoneにする)
# }
job_status = {}


# Sentry Logger
try:
    sentry_sdk.init(
        dsn=config.SENTRY_DSN,
        integrations=[FlaskIntegration()],

        # Set traces_sample_rate to 1.0 to capture 100%
        # of transactions for performance monitoring.
        # We recommend adjusting this value in production.
        traces_sample_rate=1.0
    )
except AttributeError:
    pass

app = Flask(__name__)
# ランダムバイトから鍵生成
app.secret_key = bytes(bytearray(random.getrandbits(8) for _ in range(32)))
app.permanent_session_lifetime = timedelta(hours=1)

request_session = requests.Session()
request_session.headers.update({'User-Agent': USER_AGENT})

@app.route('/')
def root():
    return render_template('index.html')

@app.route('/login', methods=['POST'])
def login():
    data = request.form
    if not data.get('type'):
        return make_response('type is required', 400)
    if not data.get('hostname'):
        return make_response('hostname is required', 400)
    if not data.get('import_size'):
        return make_response('import_size is required', 400)
    #if not data.get('noImportPrivatePost'):
        #return make_response('noImportPrivatePost is required', 400)

    import_size_str = data['import_size']
    try:
        import_size = int(data['import_size'])
    except:
        return make_response('import_size is invalid', 400)
    
    if import_size < 1000 or import_size > 20000:
        return make_response('import_size is must be between 1000 and 20000', 400)
    
    session['import_size'] = import_size
    
    if data['type'] == 'misskey':
        session['logged_in'] = False
        session.permanent = True
        session['hostname'] = data['hostname']
        session['type'] = data['type']
        session['noImportPrivatePost'] = data.get('noImportPrivatePost', False)
        session['allowGenerateByOther'] = data.get('allowGenerateByOther', False)
        session['hasModelData'] = False

        try:
            mi = Misskey(address=data['hostname'], session=request_session)
        except requests.exceptions.ConnectionError:
            return make_response('<meta name="viewport" content="width=device-width">インスタンスと通信できませんでした。(ConnectionError)', 500)
        instance_info = mi.meta()

        if instance_info['features'].get('miauth') == True:
            miauth = MiAuth(address=data['hostname'], name='markov-generator-fedi', callback=f'{request.host_url}login/callback', permission=[Permissions.READ_ACCOUNT], session=request_session)
            url = miauth.generate_url()
            session['session_id'] = miauth.session_id
            session['mi_legacy'] = False
            return redirect(url)
        else:
            # v12.39.1以前のインスタンス向け
            options = {
                'name': 'markov-generator-fedi (Legacy)',
                'callback': f'{request.host_url}login/callback',
                'permission': ['read:account'],
                'description': 'Created by CyberRex (@cyberrex_v2@misskey.io)',
                'callbackUrl': f'{request.host_url}login/callback',
            }

            r = requests.post(f'https://{data["hostname"]}/api/app/create', json=options, headers={'User-Agent': USER_AGENT})
            if r.status_code != 200:
                return make_response(f'Failed to generate app: {r.text}', 500)
            j = r.json()

            secret_key = j['secret']

            r = requests.post(f'https://{data["hostname"]}/api/auth/session/generate', json={'appSecret': secret_key}, headers={'User-Agent': USER_AGENT})
            if r.status_code != 200:
                return make_response(f'Failed to generate session: {r.text}', 500)
            j = r.json()
            
            session['mi_session_token'] = j['token']
            session['mi_secret_key'] = secret_key
            session['mi_legacy'] = True
            return redirect(j['url'])
    
    if data['type'] == 'mastodon':
        session['logged_in'] = False
        session.permanent = True
        session['hostname'] = data['hostname']
        session['type'] = data['type']
        session['noImportPrivatePost'] = data.get('noImportPrivatePost', False)
        session['allowGenerateByOther'] = data.get('allowGenerateByOther', False)
        session['hasModelData'] = False
        
        options = {
            'client_name': 'markov-generator-fedi',
            'redirect_uris': f'{request.host_url}login/callback',
            'scopes': 'read write'
        }
        r = requests.post(f'https://{data["hostname"]}/api/v1/apps', json=options, headers={'User-Agent': USER_AGENT})
        if r.status_code != 200:
            return make_response(f'Failed to regist app: {r.text}', 500)
        d = r.json()
        session['mstdn_app_key'] = d['client_id']
        session['mstdn_app_secret'] = d['client_secret']
        session['mstdn_redirect_uri'] = f'{request.host_url}login/callback'

        querys = {
            'client_id': d['client_id'],
            'response_type': 'code',
            'redirect_uri': f'{request.host_url}login/callback',
            'scopes': 'read write',
        }

        return redirect(f'https://{data["hostname"]}/oauth/authorize?{urllib.parse.urlencode(querys)}')
    
    return 'How did you come to here'
    
@app.route('/login/callback')
def login_msk_callback():
    if not ('logged_in' in list(session.keys())):
        return make_response('<meta name="viewport" content="width=device-width">セッションデータが異常です。Cookieを有効にしているか確認の上再試行してください。<a href="/">トップページへ戻る</a>', 400)

    if session['type'] == 'misskey':

        if not session['mi_legacy']:

            miauth = MiAuth(session['hostname'] ,session_id=session['session_id'], session=request_session)
            try:
                token = miauth.check()
            except MisskeyMiAuthFailedException:
                session.clear()
                return make_response('<meta name="viewport" content="width=device-width">認証に失敗しました。', 500)
            session['token'] = token

        else:
            secret_key = session['mi_secret_key']
            session_token = session['mi_session_token']
            r = requests.post(f'https://{session["hostname"]}/api/auth/session/userkey', json={'appSecret': secret_key, 'token': session_token}, headers={'User-Agent': USER_AGENT})
            if r.status_code != 200:
                return make_response(f'Failed to generate session: {r.text}', 500)
            j = r.json()

            access_token = j['accessToken']
            ccStr = f'{access_token}{secret_key}'
            token = hashlib.sha256(ccStr.encode('utf-8')).hexdigest()

        mi: Misskey = Misskey(address=session['hostname'], i=token, session=request_session)
        i = mi.i()

        session['username'] = i['username']
        session['acct'] = f'{i["username"]}@{session["hostname"]}'
        session['user_id'] = i['id']

        thread_id = str(uuid.uuid4())
        job_status[thread_id] = {
            'completed': False,
            'error': None,
            'progress': 1,
            'progress_str': '初期化中です'
        }

        noImportPrivate = session['noImportPrivatePost']
        allowGenerateByOther = session['allowGenerateByOther']

        def proc(job_id, data):

            st = time.time()
            
            job_status[job_id]['progress'] = 20
            job_status[job_id]['progress_str'] = '投稿を取得しています...'

            # 学習に使うノートを取得
            notes = []
            kwargs = {}
            withfiles = False
            mi2: Misskey = Misskey(address=data['hostname'], i=token, session=request_session)
            userdata_block = mi2.users_show(user_id=data['user_id'])

            took_time_array = []

            for i in range(int(data['import_size']/100)):
                t = time.time()
                notes_block = mi2.users_notes(data['user_id'], include_replies=False, include_my_renotes=False, with_files=withfiles, limit=100, **kwargs)
                if not notes_block:
                    if not withfiles:
                        withfiles = True
                        continue
                    else:
                        break
                else:
                    kwargs['until_id'] = notes_block[-1]['id']
                    # notes.extend(notes_block)
                    for note in notes_block:
                        if noImportPrivate:
                            if not (note['visibility'] == 'public' or note['visibility'] == 'home'):
                                continue
                        notes.append(note)
                job_status[job_id]['progress'] = 20 + ((i/int(userdata_block['notesCount']/100))*60)

                # 残り時間計算
                if took_time_array:
                    avg_took_time = sum(took_time_array) / len(took_time_array)
                    est = (avg_took_time) * ((int(userdata_block['notesCount'])/100) - i)
                    est_min = math.floor(est/60)
                    est_sec = math.floor(est%60)
                    job_status[job_id]['progress_str'] = f'投稿を取得しています。 (残 {str(est_min)+"分" if est_min>0 else ""}{est_sec}秒)'
                
                took_time_array.append(time.time() - t)

            # 解析用に文字列整形
            lines = []
            for note in notes:
                if note['text']:
                    if len(note['text']) > 2:
                        for l in note['text'].splitlines():
                            lines.append(format_text(l))
            
            job_status[job_id]['progress_str'] = 'モデルを作成しています'
            job_status[job_id]['progress'] = 80

            try:
                text_model = create_markov_model_by_multiline(lines)
            except Exception as e:
                job_status[job_id] = {
                    'completed': True,
                    'error': str(e),
                }
                return
            
            job_status[job_id]['progress_str'] = 'データベースに書き込み中です'
            job_status[job_id]['progress'] = 90

            # モデル保存
            try:
                cur = db.cursor()
                cur.execute('REPLACE INTO model_data(acct, data, allow_generate_by_other) VALUES (?, ?, ?)', (data['acct'], text_model.to_json(), int(allowGenerateByOther == 'on')))
                cur.close()
                db.commit()
            except:
                print(traceback.format_exc())
                job_status[job_id] = {
                    'completed': True,
                    'error': 'Failed to save model',
                }
                return
            
            job_status[job_id] = {
                'completed': True,
                'error': None,
                'progress': 100,
                'progress_str': '完了',
                'result': f'取り込み済投稿数: {len(notes)}<br>処理時間: {(time.time() - st)*1000:.2f} ミリ秒'
            }

        thread = threading.Thread(target=proc, args=(thread_id, {
            'hostname': session['hostname'],
            'token': token,
            'acct': session['acct'],
            'user_id': session['user_id'],
            'import_size': session['import_size']
        }), name=thread_id)
        thread.start()

        job_status[thread_id]['thread'] = thread

        session['logged_in'] = True
        return redirect('/job_wait?job_id=' + thread_id)
    
    if session['type'] == 'mastodon':
        
        auth_code = request.args.get('code')
        if not auth_code:
            return make_response('<meta name="viewport" content="width=device-width">認証に失敗しました。', 500)
        
        r = requests.post(f'https://{session["hostname"]}/oauth/token', json={
            'grant_type': 'authorization_code',
            'client_id': session['mstdn_app_key'],
            'client_secret': session['mstdn_app_secret'],
            'redirect_uri': session['mstdn_redirect_uri'],
            'scope': 'read write',
            'code': auth_code
        }, headers={'User-Agent': USER_AGENT})
        if r.status_code != 200:
            return make_response(f'Failed to get token: {r.text}', 500)
        
        d = r.json()
        token = d['access_token']

        r = requests.get('https://' + session['hostname'] + '/api/v1/accounts/verify_credentials', headers={'Authorization': f'Bearer {token}', 'User-Agent': USER_AGENT})
        if r.status_code != 200:
            return make_response(f'Failed to verify credentials: {r.text}', 500)

        account = r.json()

        session['username'] = account['username']
        session['acct'] = f'{session["username"]}@{session["hostname"]}'
        
        thread_id = str(uuid.uuid4())
        job_status[thread_id] = {
            'completed': False,
            'error': None,
            'progress': 1,
            'progress_str': '初期化中です',
            'thread': None
        }

        noImportPrivate = session['noImportPrivatePost']
        allowGenerateByOther = session['allowGenerateByOther']

        def proc(job_id, data):

            st = time.time()

            job_status[job_id]['progress'] = 20
            job_status[job_id]['progress_str'] = '投稿を取得しています。'

            mstdn = mastodon.Mastodon(client_id=data['mstdn_app_key'], client_secret=data['mstdn_app_secret'], access_token=token, api_base_url=f'https://{data["hostname"]}', session=request_session)
            toots = mstdn.account_statuses(account['id'], limit=data['import_size'])

            job_status[job_id]['progress'] = 50

            # 解析用に文字列整形
            lines = []
            imported_toots = 0
            for toot in toots:
                if not (toot['visibility'] == 'public' or toot['visibility'] == 'unlisted'):
                    continue
                imported_toots += 1
                if toot['content']:
                    if len(toot['content']) > 2:
                        for l in toot['content'].splitlines():
                            tx = re.sub(r'<[^>]*>', '', l)
                            lines.append(format_text(tx))
            
            job_status[job_id]['progress_str'] = 'モデルを作成しています'
            job_status[job_id]['progress'] = 80

            try:
                text_model = create_markov_model_by_multiline(lines)
            except Exception as e:
                job_status[job_id] = {
                    'completed': True,
                    'error': 'Failed to create model: ' + str(e)
                }
                return

            job_status[job_id]['progress_str'] = 'データベースに書き込み中です'
            job_status[job_id]['progress'] = 90

            # モデル保存
            try:
                cur = db.cursor()
                cur.execute('REPLACE INTO model_data(acct, data, allow_generate_by_other) VALUES (?, ?, ?)', (data['acct'], text_model.to_json(), int(allowGenerateByOther == 'on')))
                cur.close()
                db.commit()
            except:
                print(traceback.format_exc())
                job_status[job_id] = {
                    'completed': True,
                    'error': 'Failed to save model to database'
                }
                return
            
            job_status[job_id] = {
                'completed': True,
                'error': None,
                'progress': 100,
                'progress_str': '完了',
                'result': f'取り込み済投稿数: {len(imported_toots)}<br>処理時間: {(time.time() - st)*1000:.2f} ミリ秒'
            }
        
        thread = threading.Thread(target=proc, args=(thread_id,{
            'hostname': session['hostname'],
            'mstdn_app_key': session['mstdn_app_key'],
            'mstdn_app_secret': session['mstdn_app_secret'],
            'acct': session['acct'],
            'import_size': session['import_size']
        }), name=thread_id)
        thread.start()

        job_status[thread_id]['thread'] = thread

        session['logged_in'] = True
        return redirect('/job_wait?job_id=' + thread_id)

@app.route('/error_test')
def error_test():
    return render_template('job_error.html', job={'error': request.args.get('text')})

@app.route('/job_wait')
def job_wait():
    job_id = request.args.get('job_id')
    if not job_id:
        return make_response('<meta name="viewport" content="width=device-width">Invaild job id', 400)
    
    if job_id not in list(job_status.keys()):
        return make_response('<meta name="viewport" content="width=device-width">No such job', 400)
    
    # job_wait.html で自動リロードしながら待機させる

    if not job_status[job_id]['completed']:
        # thread is dead
        if not job_status[job_id]['thread'].is_alive():
            return make_response(render_template('job_error.html', message='スレッドが異常終了しました'), 500)
        
        return render_template('job_wait.html', d=job_status[job_id])
    
    if job_status[job_id]['error']:
        return make_response(render_template('job_error.html', message=job_status[job_id]['error']), 500)

    # ジョブ完了時
    session['hasModelData'] = True
    job = job_status.pop(job_id)
    return render_template('job_result.html', job=job)

@app.route('/generate')
def generate_page():
    return render_template('generate.html', text=None, acct='', share_text='', up=urllib.parse)

@app.route('/generate/do', methods=['GET'])
def generate_do():
    query = request.args
    
    min_words = 1
    startswith = ''
    if query.get('min_words'):
        if query['min_words'].isdigit():
            min_words = int(query['min_words'])
            if min_words < 1:
                min_words = 1
            if min_words > 50:
                min_words = 50
    
    if query.get('startswith'):
        startswith = query['startswith'].strip()
        if len(startswith) > 10:
            startswith = startswith[:10]

    if not query.get('acct'):
        if not session.get('logged_in'):
            return render_template('generate.html', internal_error=True, internal_error_message='自分の投稿から文章を作るにはログインしてください <a href="/#loginModal">ログインする</a>', text='', splited_text=[], share_text='', min_words=min_words)
        
        # 自分のデータで作る
        acct = session['acct']
        if acct.startswith('@'):
            acct = acct[1:]

        cur = db.cursor()
        cur.execute('SELECT data FROM model_data WHERE acct = ?', (acct,))
        data = cur.fetchone()
        cur.close()

        if not data:
            return render_template('generate.html', internal_error=True, internal_error_message='学習データが見つかりませんでした。 <a href="/logout">ログアウト</a>してから再度ログインしてください。', text='', splited_text=[], acct=acct, share_text='', min_words=min_words)
    else:
        acct = query['acct']
        if acct.startswith('@'):
            acct = acct[1:]

        cur = db.cursor()
        cur.execute('SELECT allow_generate_by_other FROM model_data WHERE acct = ?', (acct,))
        data = cur.fetchone()
        if not data:
            return render_template('generate.html', internal_error=True, internal_error_message=f'{acct} の学習データは見つかりませんでした。', text='', splited_text=[], acct=acct, share_text='', min_words=min_words)
        
        print(session.get('acct'), acct)
        
        allow_generate_by_other = bool(data['allow_generate_by_other'])
        if (session.get('acct') != acct) and (not allow_generate_by_other):
            return render_template('generate.html', internal_error=True, internal_error_message='このユーザーは他のユーザーからの文章生成を許可していません。', text='', splited_text=[], acct=acct, share_text='', min_words=min_words)

        cur = db.cursor()
        cur.execute('SELECT data FROM model_data WHERE acct = ?', (acct,))
        data = cur.fetchone()
        cur.close()

    text_model = markovify.Text.from_json(data['data'])
    markov_params = dict(
        tries=100,
        min_words=min_words
    )

    loop_count = 1
    sw_failed = False
    if startswith:
        loop_count = 256

    st = time.perf_counter()

    try:
        if startswith:
            gen_text = text_model.make_sentence_with_start(startswith, **markov_params)
        else:
            gen_text = text_model.make_sentence(**markov_params)
        text = gen_text.replace(' ', '')
        splited_text = ['<span class="badge bg-info">' + html.escape(t) + '</span>' for t in gen_text.split(' ')]
    except AttributeError:
        text = None
    except markovify.text.ParamError:
        text = None
        if startswith:
            sw_failed = True
    except KeyError:
        text = None
        if startswith:
            sw_failed = True

    
    et = time.perf_counter()
    proc_time = (et - st) * 1000
    
    if sw_failed:
        m = json.loads(data['data'])
        chain = json.loads(m['chain'])
        first_chains = list(chain[0][1].keys())
        del m
        del chain
        word_lv_ratios = []
        for c in first_chains:
            word_lv_ratios.append(
                dict(word=c, ratio=levsh.ratio(startswith, c))
            )
        word_lv_ratios.sort(key=lambda x: x['ratio'], reverse=True)
        sw_suggest = ' '.join([f'「{x["word"]}」' for x in word_lv_ratios[:5]])


    if not text:
        return render_template('generate.html', text='', splited_text=[], acct=acct, share_text='', min_words=min_words, failed=True, proc_time=proc_time, sw_failed=sw_failed, sw_suggest=sw_suggest)

    share_text = f'{text}\n\n{acct}\n#markov-generator-fedi\n{request.host_url}generate?preset={urllib.parse.quote(acct)}&min_words={min_words}{"&startswith=" + urllib.parse.quote(startswith) if startswith else ""}'
        
    return render_template('generate.html', text=text, splited_text=splited_text, acct=acct, share_text=urllib.parse.quote(share_text), min_words=min_words, failed=False, proc_time=proc_time, model_data_size=format_bytes(len(data['data'].encode())))

@app.route('/my/delete-model-data', methods=['POST'])
def my_delete_model_data():

    if not session.get('logged_in'):
        return make_response('Please login<br><a href="/">Top</a>', 401)

    if not session.get('acct'):
        return make_response('no acct', 400)

    if request.form.get('agreeDelete') != 'on':
        return 'Canceled.<br><a href="/">Top</a>'
    
    cur = db.cursor()
    cur.execute('SELECT COUNT(*) FROM model_data WHERE acct = ?', (session['acct'],))
    res = cur.fetchone()
    cur.close()

    if res == 0:
        return 'No data found<br><a href="/">Top</a>'

    cur = db.cursor()
    cur.execute('DELETE FROM model_data WHERE acct = ?', (session['acct'],))
    cur.close()
    db.commit()

    session['hasModelData'] = False

    return 'Deleted successfully!<br><a href="/">Top</a>'

@app.route('/privacy')
def privacy_page():
    return render_template('privacypolicy.html')

@app.route('/logout')
def logout():
    session.clear()
    return redirect('/')


PORT = 8888
DEBUG = True

try:
    PORT = config.PORT
except AttributeError:
    pass

try:
    DEBUG = config.DEBUG
except AttributeError:
    pass

app.run(host='127.0.0.1', port=PORT, debug=DEBUG, threaded=True)