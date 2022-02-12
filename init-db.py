import sqlite3, os

try:
    os.remove('markov.db')
except PermissionError:
    print('Cannot remove markov.db because file is in use or no permission.')
except Exception as e:
    print(f'Cannot remove markov.db: {e!r}')
    pass

db = sqlite3.connect('markov.db')

print('Initalizing database...', end='')

cur = db.cursor()
cur.execute('CREATE TABLE IF NOT EXISTS model_data (acct TEXT NOT NULL, data TEXT NOT NULL, PRIMARY KEY ("acct"))')
cur.close()

db.commit()
db.close()

print('OK')