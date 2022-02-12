import traceback
from flask import Flask, make_response, render_template, request, redirect, session
import mastodon
from misskey import Misskey, MiAuth
from misskey.exceptions import *
import requests
import random
from datetime import timedelta
import urllib.parse
import sqlite3
import re
import MeCab
import markovify
import config

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
    return t

db = sqlite3.connect('markov.db', check_same_thread=False)
db.row_factory = dict_factory

app = Flask(__name__)
# ランダムバイトから鍵生成
app.secret_key = bytes(bytearray(random.getrandbits(8) for _ in range(32)))
app.permanent_session_lifetime = timedelta(hours=1)

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
    
    if data['type'] == 'misskey':
        session['logged_in'] = False
        session.permanent = True
        miauth = MiAuth(address=data['hostname'], name='markov-generator-fedi', callback=f'{request.host_url}login/callback')
        url = miauth.generate_url()
        session['session_id'] = miauth.session_id
        session['hostname'] = data['hostname']
        session['type'] = data['type']
        return redirect(url)
    
    if data['type'] == 'mastodon':
        session['logged_in'] = False
        session.permanent = True
        client = mastodon.Mastodon(api_base_url=f'https://{data["hostname"]}')
        app = client.create_app(client_name='markov-generator-fedi', redirect_uris=[f'{request.host_url}login/callback'], scopes=['read', 'write'])
        session['mstdn_app_key'] = app[0]
        session['mstdn_app_secret'] = app[1]

        querys = {
            'client_id': app[0],
            'response_type': 'code',
            'redirect_uris': f'{request.host_url}login/callback',
            'scope': 'read:accounts write:accounts',
        }
        
        return redirect(f'https://{data["hostname"]}/oauth/authorize?{urllib.parse.urlencode(querys)}')
    
    return 'How did you come to here'
    
@app.route('/login/callback')
def login_msk_callback():
    if not ('logged_in' in list(session.keys())):
        return make_response('セッションデータが異常です。Cookieを有効にしているか確認の上再試行してください。', 400)

    if session['type'] == 'misskey':

        miauth = MiAuth(session['hostname'] ,session_id=session['session_id'])
        try:
            token = miauth.check()
        except MisskeyMiAuthFailedException:
            return make_response('認証に失敗しました。', 500)
        session['token'] = token

        mi: Misskey = Misskey(address=session['hostname'], i=token)
        i = mi.i()

        session['username'] = i['username']
        session['acct'] = f'{i["username"]}@{session["hostname"]}'
        session['user_id'] = i['id']

        # 学習に使うノートを取得
        notes = []
        kwargs = {}
        for i in range(50):
            notes_block = mi.users_notes(session['user_id'], include_replies=False, include_my_renotes=False, limit=100, **kwargs)
            if not notes_block:
                break
            else:
                kwargs['until_id'] = notes_block[-1]['id']
                notes.extend(notes_block)

        # 解析用に文字列整形
        lines = []
        for note in notes:
            if note['text']:
                if len(note['text']) > 2:
                    for l in note['text'].splitlines():
                        lines.append(format_text(l))
        
        # MeCabで形態素解析
        parsed_text = []
        for line in lines:
            parsed_text.append(MeCab.Tagger('-Owakati').parse(line))
        
        # モデル作成
        try:
            text_model = markovify.NewlineText('\n'.join(parsed_text), state_size=2)
        except:
            return make_response('モデル作成に失敗しました。学習に必要な投稿数が不足している可能性があります。', 500)

        # モデル保存
        try:
            cur = db.cursor()
            cur.execute('REPLACE INTO model_data(acct, data) VALUES (?, ?)', (session['acct'], text_model.to_json()))
            cur.close()
            db.commit()
        except:
            print(traceback.format_exc())
            return make_response('データベースに書き込めませんでした。', 500)

        session['logged_in'] = True
        return redirect('/generate')
    
    if session['type'] == 'mastodon':
        pass

@app.route('/generate')
def generate_page():
    return render_template('generate.html', text=None, acct='', share_text='')

@app.route('/generate/do', methods=['GET'])
def generate_do():
    query = request.args

    if not query.get('acct'):
        if not session.get('logged_in'):
            return 'ログインしてください <a href="/#loginModal">ログインする</a>'
        
        # 自分のデータで作る
        acct = session['acct']
        if acct.startswith('@'):
            acct = acct[1:]

        cur = db.cursor()
        cur.execute('SELECT * FROM model_data WHERE acct = ?', (acct,))
        data = cur.fetchone()
        cur.close()

        if not data:
            return '学習データが見つかりませんでした。 <a href="/logout">ログアウト</a>してから再度ログインしてください。'
    else:
        acct = query['acct']
        if acct.startswith('@'):
            acct = acct[1:]

        cur = db.cursor()
        cur.execute('SELECT * FROM model_data WHERE acct = ?', (acct,))
        data = cur.fetchone()
        cur.close()

        if not data:
            return f'{acct} の学習データが見つかりませんでした。 '

    text_model = markovify.Text.from_json(data['data'])
    text = text_model.make_sentence(tries=100).replace(' ', '')
    if not text:
        return '文章の生成に失敗しました'

    share_text = f'{text}\n\n{acct}\n#markov-generator-fedi'
        
    return render_template('generate.html', text=text, acct=acct, share_text=urllib.parse.quote(share_text))

@app.route('/logout')
def logout():
    session.clear()
    return redirect('/')


app.run(host='127.0.0.1', port=getattr(config, 'PORT') or 8888, debug=True, threaded=True)