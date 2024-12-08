from flask import Flask,render_template,url_for,request,redirect,session,jsonify
import sqlite3

#Libreria para la gestion de los has en passwords
from werkzeug.security import generate_password_hash, check_password_hash

from functools import wraps

app = Flask(__name__)
app.secret_key = 'miclavesecreta'
#creacin de base de datos
def init_db():
    conn = sqlite3.connect("kronos.db")
    cursor =  conn.cursor()
    cursor.execute(
        """
        CREATE TABLE IF NOT EXISTS usuarios(
            carnet INTEGER PRIMARY KEY,
            nombre TEXT NOT NULL,
            apellido TEXT NOT NULL,
            username TEXT NOT NULL,
            password TEXT NOT NULL
        )
        """
    )
    cursor.execute(
        """
     CREATE TABLE IF NOT EXISTS docente(
            carnet_doc INTEGER PRIMARY KEY,
            nombre TEXT NOT NULL,
            apellido TEXT NOT NULL,
            titulo TEXT NOT NULL,
            username TEXT NOT NULL,
            password TEXT NOT NULL
        )
        """
    )
    cursor.execute(
        """
         CREATE TABLE IF NOT EXISTS curso(
            codigo INTEGER PRIMARY KEY,
            nombre TEXT NOT NULL,
            descripcion TEXT NOT NULL,
            ci_docente INTEGER NOT NULL,
            FOREIGN KEY(ci_docente) REFERENCES docente(carnet_doc)
            
        )
        """
    )
    conn.commit()
    conn.close()

init_db() 

#login
def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            return redirect("/login")
        return f(*args, **kwargs)
    return decorated_function
    
#ruta inicio
@app.route("/")
def index():
    return render_template("auth/login.html")

#funcion verificacion 
def existe(carnet):
    conn =  sqlite3.connect("kronos.db")
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM usuarios WHERE carnet = ?",(carnet,))   
    resultado=cursor.fetchone()
    conn.close()
    return resultado is not None

#ruta registrar
@app.route("/register",methods=['GET','POST'])
def register():
    if request.method == 'POST':
        carnet =  request.form['carnet']
        nombre =  request.form['nombre']
        apellido =  request.form['apellido']
        username = request.form['username']
        password = request.form['password']
        if existe(carnet):
            return jsonify({'message':' EL CARNET YA FUE REGISTRADO '})
        else:
        # Encriptar el password
            password_encriptado =  generate_password_hash(password)
        # Almacenar en la base de datos
            conn =  sqlite3.connect("kronos.db")
            cursor = conn.cursor()
            cursor.execute("INSERT INTO usuarios (carnet,nombre,apellido,username,password) VALUES (?,?,?,?,?)",(carnet,nombre,apellido,username,password_encriptado))
            conn.commit()
            conn.close()
            return render_template('confirmacion.html')
    
    

#ruta login
@app.route("/login",methods=['GET','POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        
        conn =  sqlite3.connect("kronos.db")
        # Permite obtener registros como diccionario
        conn.row_factory =  sqlite3.Row
        cursor =  conn.cursor()
        cursor.execute("SELECT * FROM usuarios WHERE username = ?",(username,))
        usuario = cursor.fetchone()
        conn.close()
        
        if usuario and check_password_hash(usuario['password'],password):
            session['user_id'] = usuario['carnet']
            return redirect('/ret')
                
    return render_template('auth/login.html')

#ruta salir
@app.route("/logout")
def logout():
    session.pop('user_id',None)
    return redirect("/")

#ruta index
@app.route("/ret")
@login_required
def ret():
    return render_template('index.html')
    
#ruta administrador
@app.route("/admin/dashboard")
@login_required
def dashboard():
    return render_template('admin/dashboard.html')

#funcion obtener datos
def obtener_datos():
    conn = sqlite3.connect('kronos.db')
    cursor = conn.cursor()
    cursor.execute('SELECT carnet, nombre, apellido, username FROM usuarios')
    datos = cursor.fetchall()
    conn.close()
    return datos

#ruta mostrar datos
@app.route('/datos')
@login_required
def mostrar_datos():
    datos = obtener_datos()
    return render_template('datos.html', usuarios=datos)

#ruta cursos
@app.route("/cursos")
@login_required
def cursos():
    datos = obtener_datos()
    return render_template('cursos.html',usuarios=datos)

#ruta eliminar datos
@app.route('/borrar/<int:carnet>', methods=['POST']) 
def borrar_dato(carnet): 
    conn = sqlite3.connect('kronos.db') 
    cursor = conn.cursor() 
    cursor.execute('DELETE FROM usuarios WHERE carnet= ?', (carnet,)) 
    conn.commit() 
    conn.close() 
    return redirect(url_for('mostrar_datos'))


if __name__ == "__main__":
    app.run(debug=True)
