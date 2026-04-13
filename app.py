from flask import Flask, render_template, request, flash
from analyzer import PasswordAnalyzer
import sqlite3

app = Flask(__name__)
app.secret_key = 'super_secret_key'
analyzer = PasswordAnalyzer()

def init_db():
    with sqlite3.connect('passwords.db') as conn:
        conn.execute('CREATE TABLE IF NOT EXISTS history (hash TEXT UNIQUE)')

@app.route('/', methods=['GET', 'POST'])
def index():
    result = None
    suggestion = None
    
    if request.method == 'POST':
        user_password = request.form.get('password')
        pwd_hash = analyzer.hash_password(user_password)
        
        # Check Database for reuse
        with sqlite3.connect('passwords.db') as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT * FROM history WHERE hash=?", (pwd_hash,))
            if cursor.fetchone():
                flash("Error: You have used this password before!", "danger")
            else:
                result = analyzer.evaluate(user_password)
                if result['strength'] != "Strong":
                    suggestion = analyzer.generate_strong_password()
                
                # If strong enough, "save" it (optional logic)
                if result['score'] >= 3:
                    cursor.execute("INSERT INTO history (hash) VALUES (?)", (pwd_hash,))
                    conn.commit()

    return render_template('index.html', result=result, suggestion=suggestion)

if __name__ == '__main__':
    init_db()
    app.run(debug=True)