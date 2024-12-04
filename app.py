from flask import Flask,render_template,url_for,request,redirect,session
import sqlite3

#Libreria para la gestion de los has en passwords
from werkzeug.security import generate_password_hash, check_password_hash

from functools import wraps

app = Flask(__name__)
app.secret_key = 'miclavesecreta'

def init_db():
    conn = sqlite3.connect("inventarios.db")
    cursor =  conn.cursor()
    cursor.execute(
        """
        CREATE TABLE IF NOT EXISTS usuarios(
            id INTEGER PRIMARY KEY,
            nombre TEXT NOT NULL,
            username TEXT NOT NULL,
            password TEXT NOT NULL
        )
        """
    )
    conn.commit()
    conn.close()

init_db() 

def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            return redirect("/login")
        return f(*args, **kwargs)
    return decorated_function
    
@app.route("/")
def index():
    return render_template("auth/login.html")

@app.route("/register",methods=['GET','POST'])
def register():
    if request.method == 'POST':
        nombre =  request.form['nombre']
        username = request.form['username']
        password = request.form['password']
        # Encriptar el password
        password_encriptado =  generate_password_hash(password)
        # Almacenar en la base de datos
        conn =  sqlite3.connect("inventarios.db")
        cursor = conn.cursor()
        cursor.execute("INSERT INTO usuarios (nombre,username,password) VALUES (?,?,?)",(nombre, username,password_encriptado))
        conn.commit()
        conn.close()
        return redirect("/ret")
        
    return render_template('index.html')

@app.route("/login",methods=['GET','POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        
        conn =  sqlite3.connect("inventarios.db")
        # Permite obtener registros como diccionario
        conn.row_factory =  sqlite3.Row
        cursor =  conn.cursor()
        cursor.execute("SELECT * FROM usuarios WHERE username = ?",(username,))
        usuario = cursor.fetchone()
        conn.close()
        
        if usuario and check_password_hash(usuario['password'],password):
            session['user_id'] = usuario['id']
            return redirect('/ret')
                
    return render_template('auth/login.html')
    
@app.route("/logout")
def logout():
    session.pop('user_id',None)
    return redirect("/")

@app.route("/ret")
@login_required
def ret():
    return render_template('index.html')
    
@app.route("/admin/dashboard")
@login_required
def dashboard():
    return render_template('admin/dashboard.html')

def obtener_datos():
    conn = sqlite3.connect('inventarios.db')
    cursor = conn.cursor()
    cursor.execute('SELECT id, nombre FROM usuarios')
    datos = cursor.fetchall()
    conn.close()
    return datos

@app.route('/datos')
@login_required
def mostrar_datos():
    datos = obtener_datos()
    return render_template('datos.html', usuarios=datos)

@app.route('/borrar/<int:id>', methods=['POST']) 
def borrar_dato(id): 
    conn = sqlite3.connect('inventarios.db') 
    cursor = conn.cursor() 
    cursor.execute('DELETE FROM usuarios WHERE id = ?', (id,)) 
    conn.commit() 
    conn.close() 
    return redirect(url_for('mostrar_datos'))


if __name__ == "__main__":
    app.run(debug=True)
