import os
import sqlite3
from flask import Flask, request, session, redirect, url_for, render_template

app = Flask(__name__)
app.secret_key = "SuperSecretSessionKey"  
app.permanent_session_lifetime = 100000  # Нет времени жизни сессии
app.config['DATABASE'] = os.path.join(os.path.dirname(__file__), 'database.db')

def get_db():
    conn = sqlite3.connect(app.config['DATABASE'])
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    with app.app_context():
        db = get_db()
        with open(os.path.join(os.path.dirname(__file__), 'schema.sql'), 'r') as f:
            db.executescript(f.read())
        db.commit()

@app.route('/')
def index():
    db = get_db()
    user_count = db.execute('SELECT COUNT(*) as cnt FROM users').fetchone()['cnt']
    return render_template('base.html', user_count=user_count)

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        db = get_db()
        try:
            db.execute('INSERT INTO users (username, password) VALUES (?,?)', (username, password))
            db.commit()
            return redirect(url_for('login'))
        except sqlite3.IntegrityError:
            return "Пользователь уже существует"
    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        db = get_db()
        user = db.execute('SELECT id FROM users WHERE username=? AND password=?', (username, password)).fetchone()
        if user:
            session['user_id'] = user['id']
            session['username'] = username
            session.permanent = True
            return redirect(url_for('notes'))
        else:
            return "Неверное имя пользователя или пароль"
    return render_template('login.html')

@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('index'))

@app.route('/notes', methods=['GET', 'POST'])
def notes():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    db = get_db()
    if request.method == 'POST':
        content = request.form.get('content')
        db.execute('INSERT INTO notes (user_id, content) VALUES (?,?)', (session['user_id'], content))
        db.commit()
    user_notes = db.execute('SELECT id, content FROM notes WHERE user_id=?', (session['user_id'],)).fetchall()
    return render_template('notes.html', notes=user_notes)

@app.route('/update_note', methods=['POST'])
def update_note():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    note_id = request.form.get('note_id')
    new_content = request.form.get('new_content')
    db = get_db()
    db.execute('UPDATE notes SET content=? WHERE id=? AND user_id=?', (new_content, note_id, session['user_id']))
    db.commit()
    return redirect(url_for('notes'))

@app.route('/delete_note', methods=['POST'])
def delete_note():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    note_id = request.form.get('note_id')
    db = get_db()
    db.execute('DELETE FROM notes WHERE id=? AND user_id=?', (note_id, session['user_id']))
    db.commit()
    return redirect(url_for('notes'))

@app.route('/manage', methods=['GET'])
def admin_panel():
    if 'username' not in session or session['username'] != 'admin':
        return redirect(url_for('index'))

    db = get_db()
    users = db.execute('''SELECT u.id, u.username, COUNT(n.id) AS notes_count
                          FROM users u
                          LEFT JOIN notes n ON u.id = n.user_id
                          WHERE u.username != 'admin'
                          GROUP BY u.id, u.username''').fetchall()

    return render_template('admin.html', users=users)

@app.route('/manage/delete_user', methods=['POST'])
def admin_delete_user():
    if 'username' not in session or session['username'] != 'admin':
        return redirect(url_for('index'))
    user_id = request.form.get('user_id')
    db = get_db()
    # Удаляем заметки пользователя
    db.execute('DELETE FROM notes WHERE user_id=?', (user_id,))
    # Удаляем самого пользователя
    db.execute('DELETE FROM users WHERE id=?', (user_id,))
    db.commit()
    return redirect(url_for('admin_panel'))

if __name__ == '__main__':
    if not os.path.exists(app.config['DATABASE']):
        init_db()
    app.run(host="0.0.0.0", debug=True)