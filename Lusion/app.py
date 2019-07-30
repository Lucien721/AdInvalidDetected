import os, datetime
from flask import Flask, render_template, redirect, request, session
from forms import RegisterForm, LoginForm, publishForm, advertsForm
from flask_wtf.csrf import CSRFProtect
from passlib.hash import sha256_crypt
import sqlite3 as sql
from functools import wraps

app = Flask(__name__)
app.secret_key = os.urandom(24)

csrf = CSRFProtect()
csrf.init_app(app)

proofAddress = 'proofs\\clKnownValues_proof.xml'


def wapper_isproof(func):
    @wraps(func)
    def inner(*args, **kwargs):
        if not os.path.exists(proofAddress):
            msg = 'Where is your proof? You cannot do any operations without proof.'
            return render_template("isproof.html", msg=msg)
        return func(*args, **kwargs)
    return inner


@app.route('/')
def index():
    return home()


@app.route('/home')
def home():
    img_path = 'static\\'
    images = [(image.split('.')[0], img_path+image) for image in os.listdir(img_path)]
    if not session.get('user_info'):
        return render_template('home.html', images=images, logged='False')
    else:
        return render_template('home.html', images=images, logged='True', username=session['user_info'])


@app.route('/logout')
@wapper_isproof
def logout():
    session.pop('user_info')
    return redirect('/home')


@app.route('/register', methods=['POST', 'GET'])
@wapper_isproof
def register():
    form = RegisterForm()
    if request.method == 'GET':
        return render_template('register.html', msg='', form=form)
    if form.validate_on_submit():
        try:
            username = form.username.data
            password = sha256_crypt.encrypt(form.password.data)
            #
            phoneNumber = form.phoneNumber.data
            #
            ip = request.remote_addr
            with sql.connect("database.db") as con:
                cur = con.cursor()
                # if user name is existing,
                is_existing = cur.execute('SELECT * FROM users WHERE username = ?', (username,))
                if is_existing.fetchone():
                    msg = "User name is already existing."
                    return render_template('register.html', msg=msg, form=form)
                cur.execute("INSERT INTO users (username, password, phoneNumber, ip) VALUES(?, ?, ?, ?)", (username, password, phoneNumber, ip))
                con.commit()
                msg = "Register successfully added."
                return render_template('register.html', msg=msg, form=form)
        except:
            con.rollback()
            msg = "Error in register."
            return render_template('register.html', msg=msg, form=form)
        finally:
            con.close()


@app.route('/login', methods=['POST', 'GET'])
@app.route('/login/<iflogged>', methods=['POST', 'GET'])
@wapper_isproof
def login(iflogged=None):
    form = LoginForm()
    if request.method == 'GET':
        msg = 'o(*￣▽￣*)ブ'
        print(iflogged)
        if iflogged == '1':
            msg = 'Please log in first.'
        return render_template('login.html', msg=msg, form=form)

    if form.validate_on_submit():
        username = form.username.data
        password = form.password.data
        with sql.connect("database.db") as con:
            cur = con.cursor()
            try:
                true_password = cur.execute("SELECT password from users WHERE username = ?", (username,)).fetchone()[0]
                if sha256_crypt.verify(password, true_password):
                    session['user_info'] = username
                    return redirect('/home')
                else:
                    msg = "Password is wrong, please try again."
                    return render_template('login.html', msg=msg, form=form)
            except:
                msg = "User is not existing, please try again."
                return render_template('login.html', msg=msg, form=form)


@app.route('/advert/<ID>')
@wapper_isproof
def advert(ID):
    with sql.connect("database.db") as con:
        cur = con.cursor()
        amount = float(cur.execute("SELECT Amount from adverts WHERE advertName = ?", (ID,)).fetchone()[0])
        print(os.path.exists(proofAddress))
        if amount > 0:
            cur.execute("UPDATE adverts SET clickNumber = clickNumber + 1 WHERE advertName = ?", (ID,))
            cur.execute("UPDATE adverts SET Amount = Amount - 10.0 WHERE advertName = ?", (ID,))
            con.commit()
            username = 'ANONYMOUS'
            ip = request.remote_addr
            clickTime = datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')
            if session.get('user_info'):
                username = session.get('user_info')
            cur.execute("INSERT INTO operations (advertName, username, proofAddress, ip, clickTime) VALUES(?, ?, ?, ?, ?)", (ID, username, proofAddress, ip, clickTime))
            con.commit()
            msg = 'So, what are you fucking watching?'
        else:
            msg = 'This Advert is gone.'
    con.close()
    return render_template("advert.html", msg=msg)


def wapper_islogged(func):
    @wraps(func)
    def inner(*args, **kwargs):
        if not session.get('user_info'):
            return redirect('/login/1')
        return func(*args, **kwargs)
    return inner


@app.route('/list')
@wapper_isproof
@wapper_islogged
def list():
    con = sql.connect("database.db")
    con.row_factory = sql.Row
    cur = con.cursor()
    cur.execute("select * from users")
    users_rows = cur.fetchall()
    cur.execute("select * from adverts")
    adverts_rows = cur.fetchall()
    cur.execute("select * from operations")
    operations_rows = cur.fetchall()
    return render_template("list.html", users_rows=users_rows, adverts_rows=adverts_rows, operations_rows=operations_rows)


@app.route('/publish',  methods=['POST', 'GET'])
@wapper_isproof
@wapper_islogged
def publish():
    form = publishForm()
    msg = ''
    if request.method == 'GET':
        return render_template("publish.html", msg=msg, form=form)
    if form.validate_on_submit():
        img_path = 'static\\'
        images = [int(image.split('.')[0]) for image in os.listdir(img_path)]
        index = str(max(images) + 1)
        form.advertImage.data.save(img_path + index + '.jpg')
        with sql.connect("database.db") as con:
            cur = con.cursor()
            cur.execute('INSERT INTO adverts (advertName, amount, clickNumber) VALUES (?, 10000.00, 0)',
                         (index,))
            con.commit()
        con.close()
        msg = 'Successfully published.'
    return render_template("publish.html", msg=msg, form=form)


if __name__ == '__main__':
    port = int(os.environ.get('PORT', 5000))
    app.run(host='127.0.0.1', port=port)