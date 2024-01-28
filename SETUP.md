# セットアップ方法
1. `virtualenv env` で環境を作成、 `. env/bin/activate` で入る
2. `pip install -U -r requirements.txt` で依存関係にあるパッケージをインストール
3. `python3 -m unidic download` で辞書をダウンロードする
4. `init-db.py` でデータベースを初期化する
5. `config.py` の `PORT` を適宜変更する (デフォルトは8888)
6. `web.py` を起動する

# config.pyの内容

```py
PORT=8888 # Webサーバーの待ち受けポート
DEBUG=True # デバッグモードで起動するか (本番環境ではFalse推奨)
MECAB_DICDIR='...' # MeCabで使用する辞書があるディレクトリの絶対パス
MECAB_RC='...' # mecabrcの絶対パス
```

# プライバシーポリシーのページについて
`templates/privacypolicy.html` に配置すると、 `/privacy` でアクセスすることができます。