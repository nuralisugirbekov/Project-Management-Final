import subprocess

import flash
import requests
from flask_sqlalchemy import SQLAlchemy
from flask import Flask, render_template, request, redirect, url_for, session
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime

from flask_mysqldb import MySQL
from flask_login import LoginManager, login_manager
from main import DecryptionModule

app = Flask(__name__, static_url_path='/static')
app.secret_key = '12345678'

app.config['MYSQL_HOST'] = 'localhost'
app.config['MYSQL_USER'] = 'root'
app.config['MYSQL_PASSWORD'] = '12345678'
app.config['MYSQL_DB'] = 'sys'

mysql = MySQL(app)

login_manager = LoginManager(app)


@app.route('/', methods=['GET', "POST"])
def result():
    if 'username' in session:
        if request.method == 'POST':
            search = request.form['method'] # input text
            key = request.form.get('key', None) #cipher key
            valid_request = True
            date=datetime.now()

            print(search, key)
            if key is not None and key.isnumeric():
                key = int(key)
            elif key is not None and key.isalpha():
                key = str(key)
            else:
                key = None
            decryption_module = DecryptionModule()
            print("1", valid_request)
            if decryption_module.status_code == 404:
                valid_request = False
                print("2", valid_request)
                return render_template('errorpage.html')
            decrypted_text, method = decryption_module.decode(search, key)[:2]
            print("3", valid_request, decrypted_text, method)

            # print(search, key)
            if decrypted_text is None:
                valid_request = False
                print("4", valid_request)
                return render_template('index.html', identified_methods=None, method="Method not identified", username=session['username'])


            if valid_request:
                print("5", valid_request)
                try:
                    cur = mysql.connection.cursor()

                    cur.execute('SELECT id FROM users WHERE username = %s', [session['username']])

                    # Fetch the result (a tuple)
                    result = cur.fetchone()

                    if result:
                        user_id = result[0]  # Extract the user ID from the tuple
                        print(user_id, session['username'])

                        cur.execute('INSERT INTO user_history (body, userID, daterequested, cipher_key, encryption_method, decrypted_text) VALUES (%s, %s, %s, %s, %s, %s)',
                                    [search, user_id, date.strftime("%Y-%m-%d, %H:%M:%S"), key, method, decrypted_text])
                        mysql.connection.commit()

                    cur.close()

                except Exception as e:
                    print("Error during database insertion:", e)
                    valid_request = False  # Fail the request in case of database errors
                    return render_template('errorpage.html')

            return render_template('index.html', identified_methods=method, method=decrypted_text, username=session['username'])

    if 'username' in session:
        return render_template('index.html', username=session['username'])
    return render_template('index.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        cur = mysql.connection.cursor()
        cur.execute('SELECT username, password FROM users WHERE username=%s', [username])
        data = cur.fetchone()
        cur.close()
        if data and check_password_hash(data[1], password):
            session['username'] = data[0]
            return redirect(url_for('result'))
        else:
            return render_template('login.html', error="Invalid username or password")

    return render_template('login.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        email = request.form['email']
        password = request.form['password']
        password = generate_password_hash(password)

        date = datetime.now()

        cur = mysql.connection.cursor()
        cur.execute('INSERT INTO users (username, email, password, datejoined) VALUES (%s, %s, %s, %s)', [username, email, password, date.strftime("%Y-%m-%d, %H:%M:%S")])
        mysql.connection.commit()
        cur.close()

        return redirect(url_for('login'))

    return render_template('register.html')

@login_manager.user_loader
def load_user(user_id):
    cur = mysql.connection.cursor()
    cur.execute('SELECT * FROM users WHERE id=%s', [user_id])
    data = cur.fetchone()
    cur.close()
    if data and user_id == data[2]:
        return data[3]


@app.route('/logout')
def logout():
    session.pop('username', None)
    return redirect(url_for('result'))

@app.route('/history')
def history():
    if 'username' in session:
        cur = mysql.connection.cursor()

        # Get the user's ID based on their username
        cur.execute('SELECT id FROM users WHERE username = %s', [session['username']])
        result = cur.fetchone()

        ctx = {'requests': []}  # Initialize context
        if result:
            user_id = result[0]  # Extract user ID
            # Query user history for the logged-in user only
            cur.execute('SELECT body, cipher_key, daterequested, encryption_method, decrypted_text FROM user_history WHERE userID = %s', [user_id])
            results = cur.fetchall()  # Fetch all records for the user

            # Process results into the context
            for record in results:
                formatted_date = record[2].strftime('%d %b %Y, %I:%M %p')
                ctx['requests'].append({
                    'body': record[0],  # Body of the request
                    'key': record[1],  # Cipher key
                    'date': formatted_date,  # Date requested
                    'method': record[3],
                    'output': record[4]
                })

        cur.close()
        return render_template('history.html', username=session['username'], context=ctx)

    return render_template('history.html')  # User is not logged in

@app.route('/clear-history', methods=['GET', 'POST'])
def clear_history():
    if 'username' in session:
        cur = mysql.connection.cursor()
        cur.execute('SELECT id FROM users WHERE username = %s', [session['username']])
        result = cur.fetchone()
        user_id=0

        if result:
            user_id = result[0]
            cur.execute(
                'SELECT body, cipher_key, daterequested, encryption_method, decrypted_text FROM user_history WHERE userID = %s',
                [user_id])
            results = cur.fetchall()
        else:
            results = []

        if request.method == 'GET':
            cur.execute('DELETE FROM user_history WHERE userID = %s', [user_id])
            mysql.connection.commit()
            cur.close()
            return redirect(url_for('history'))

        cur.close()
        return render_template('history.html', username=session['username'], context=results)

    return render_template('history.html', context=[])

if __name__ == '__main__':
    app.run(debug=True, host="localhost", port=4000)
