import sqlite3


conn = sqlite3.connect('encrypto_chat.db')
cursor = conn.cursor()


cursor.execute("SELECT name FROM sqlite_master WHERE type='table';")
tables = cursor.fetchall()
print("Tables in database:", tables)

cursor.execute("SELECT * FROM users")
data = cursor.fetchall()
for row in data:
    print(row)

cursor.execute("SELECT * FROM messages")
data = cursor.fetchall()
for row in data:
    print(row)


conn.close()
