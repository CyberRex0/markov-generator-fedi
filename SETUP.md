# セットアップ方法
1. `init-db.py` でデータベースを初期化する
2. `config.py` の `PORT` を適宜変更する (デフォルトは8888)
3. `web.py` を起動する

# config.pyの内容

```py
PORT=8888 # Webサーバーの待ち受けポート
DEBUG=True # デバッグモードで起動するか (本番環境ではFalse推奨)
```
