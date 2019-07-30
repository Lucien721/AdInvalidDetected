import sqlite3 as sql
import os
conn = sql.connect('database.db')
print("Opened database successfully.")

conn.execute('CREATE TABLE users (username TEXT, password TEXT, phoneNumber TEXT, ip TEXT)')
print("Table users created successfully.")
conn.execute('CREATE TABLE adverts (advertName TEXT, amount TEXT, clickNumber INT)')
conn.execute('CREATE TABLE operations (advertName TEXT, username TEXT, proofAddress TEXT, ip TEXT, clickTime TEXT)')
img_path = 'static\\'
for image in os.listdir(img_path):
    conn.execute('INSERT INTO adverts (advertName, amount, clickNumber) VALUES (?, 10000.00, 0)', (image.split('.')[0],))
    conn.commit()
print("Table adverts created successfully.")
conn.close()