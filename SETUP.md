# セットアップ方法
1. `pip install -U -r requirements.txt` で依存関係にあるパッケージをインストール
2. `python3.8 -m unidic download` で辞書をダウンロードする
3. `init-db.py` でデータベースを初期化する
4. `config.py` の `PORT` を適宜変更する (デフォルトは8888)
5. `web.py` を起動する

# config.pyの内容

```py
PORT=8888 # Webサーバーの待ち受けポート
DEBUG=True # デバッグモードで起動するか (本番環境ではFalse推奨)
```

# プライバシーポリシーのページについて
`templates/privacypolicy.html` に配置すると、 `/privacypolicy` でアクセスすることができます。