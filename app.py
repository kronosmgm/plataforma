from flask import Flask,flash,render_template,url_for,request,redirect,session
import sqlite3

#Libreria para la gestion de los has en passwords
from werkzeug.security import generate_password_hash, check_password_hash

from functools import wraps

app = Flask(__name__)
app.secret_key = 'miclavesecreta'
#creacion de base de datos
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
    cursor.execute(
        """
         CREATE TABLE IF NOT EXISTS admin(
            ci_adm INTEGER PRIMARY KEY,
            nombre TEXT NOT NULL,
            username TEXT NOT NULL,
            password TEXT NOT NULL
        )
        """
    )
    cursor.execute(
        """
         CREATE TABLE IF NOT EXISTS recorrido(
            id INTEGER PRIMARY KEY,
            curso INTERGET NOT NULL,
            carnet_es INTEGER NOT NULL,
            detalle TEXT NOT NULL,
            FOREIGN KEY(curso) REFERENCES curso(codigo),
            FOREIGN KEY(carnet_es) REFERENCES usuarios(carnet)
        )
        """
    )
    conn.commit()
    conn.close()

init_db() 

#vericicacion de sesion
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

#funcion verificacion curso
def existecod(codigo):
    conn =  sqlite3.connect("kronos.db")
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM curso WHERE codigo = ?",(codigo,))   
    resultado=cursor.fetchone()
    conn.close()
    return resultado is not None

#funcion verificacion usuario
def existe(carnet):
    conn =  sqlite3.connect("kronos.db")
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM usuarios WHERE carnet = ?",(carnet,))   
    resultado=cursor.fetchone()
    conn.close()
    return resultado is not None

#funcion de verificacion docente
def existe_doc(carnet_doc):
    conn =  sqlite3.connect("kronos.db")
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM docente WHERE carnet_doc = ?",(carnet_doc,))   
    resultado=cursor.fetchone()
    conn.close()
    return resultado is not None

#funcion verificacion administrador
def existe_adm(ci_adm):
    conn =  sqlite3.connect("kronos.db")
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM admin WHERE ci_adm = ?",(ci_adm,))   
    resultado=cursor.fetchone()
    conn.close()
    return resultado is not None

#funcion de verificacion username
def existeusuario(username):
    conn =  sqlite3.connect("kronos.db")
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM usuarios WHERE username = ?",(username,))   
    resultado=cursor.fetchone()
    conn.close()
    return resultado is not None

#funcion de verificacion username docente
def existeusuariodoc(username):
    conn =  sqlite3.connect("kronos.db")
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM docente WHERE username = ?",(username,))   
    resultado=cursor.fetchone()
    conn.close()
    return resultado is not None

#funcion de verificacion username administrador
def existeusuarioadm(username):
    conn =  sqlite3.connect("kronos.db")
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM admin WHERE username = ?",(username,))   
    resultado=cursor.fetchone()
    conn.close()
    return resultado is not None

#ruta login
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        role = request.form['role']
        
        conn =  sqlite3.connect("kronos.db")
        if role == 'usuario':
            conn.row_factory =  sqlite3.Row
            cursor =  conn.cursor()
            cursor.execute("SELECT * FROM usuarios WHERE username = ?",(username,))
            usuario = cursor.fetchone()
            if usuario and check_password_hash(usuario['password'],password):
                session['user_id'] = usuario['carnet']
                return redirect('/ret')
        elif role == 'docente':
            conn.row_factory =  sqlite3.Row
            cursor =  conn.cursor()
            cursor.execute("SELECT * FROM docente WHERE username = ?",(username,))
            usuario = cursor.fetchone()
            if usuario and check_password_hash(usuario['password'],password):
                session['user_id'] = usuario['carnet_doc']
                return redirect('/docentes/inicio')
        elif role == 'admin':
            conn.row_factory =  sqlite3.Row
            cursor =  conn.cursor()
            cursor.execute("SELECT * FROM admin WHERE username = ?",(username,))
            usuario = cursor.fetchone()
            if usuario and check_password_hash(usuario['password'],password):
                session['user_id'] = usuario['ci_adm']
                return redirect('/admin/dashboard')
        conn.close()
    return render_template('auth/login.html')

#ruta registrar usuario
@app.route("/register",methods=['GET','POST'])
def register():
    if request.method == 'POST':
        carnet =  request.form['carnet']
        nombre =  request.form['nombre']
        apellido =  request.form['apellido']
        username = request.form['username']
        password = request.form['password']
        if (existe(carnet) or existe_doc(carnet) or existe_adm(carnet)):
            return render_template('auth/login.html', mensaje='el numero de carnet ya se encuentra registrado.')
        else:
            if (existeusuario(username) or existeusuariodoc(username) or existeusuarioadm(username)):
                return render_template('auth/login.html', mensaje='el nombre de usuario ya existe.')
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
    return render_template('auth/login.html')

#ruta registrar doc
@app.route("/registrardoc",methods=['GET','POST'])
def reg():
    if request.method == 'POST':
        carnet_doc =  request.form['carnet_doc']
        nombre =  request.form['nombre']
        apellido =  request.form['apellido']
        titulo = request.form['titulo']
        username = request.form['username']
        password = request.form['password']
        if(existe(carnet_doc) or existe_doc(carnet_doc) or existe_adm(carnet_doc)):
            return render_template('admin/registraradmi.html', mensaje='el numero de carnet ya se encuentra registrado.')
        else:
            if (existeusuario(username) or existeusuariodoc(username) or existeusuarioadm(username)):
                return render_template('admin/registraradmi.html', mensaje='el nombre de usuario ya existe.')
            else:
        # Encriptar el password
                password_encriptado =  generate_password_hash(password)
        # Almacenar en la base de datos
                conn =  sqlite3.connect("kronos.db")
                cursor = conn.cursor()
                cursor.execute("INSERT INTO docente(carnet_doc,nombre,apellido,titulo,username,password) VALUES (?,?,?,?,?,?)",(carnet_doc,nombre,apellido,titulo,username,password_encriptado))
                conn.commit()
                conn.close()
                return render_template('admin/registraradmi.html',mensaje='docente registrado')
    return render_template('admin/dashboard.html')

#registrar curso
@app.route("/registrarcursos",methods=['GET','POST'])
def regcur():
    if request.method == 'POST':
        codigo =  request.form['codigo']
        nombre =  request.form['nombre']
        descripcion =  request.form['descripcion']
        ci_docente =  request.form['ci_docente']
        if existecod(codigo):
            return render_template('admin/registraradmi.html', mensaje='codigo repetido')
        elif existe_doc(ci_docente):
        # Almacenar en la base de datos
            conn =  sqlite3.connect("kronos.db")
            cursor = conn.cursor()
            cursor.execute("INSERT INTO curso(codigo,nombre,descripcion,ci_docente) VALUES (?,?,?,?)",(codigo,nombre,descripcion,ci_docente))
            conn.commit()
            conn.close()
        else:
            return render_template('admin/registraradmi.html', mensaje='docente no encontrado')
    return render_template('admin/registraradmi.html',mensaje='registrado')

@app.route("/registrarcursosdoc",methods=['GET','POST'])
def regcurdoc():
    if request.method == 'POST':
        codigo =  request.form['codigo']
        nombre =  request.form['nombre']
        descripcion =  request.form['descripcion']
        ci_docente =  request.form['ci_docente']
        if existecod(codigo):
            return render_template('docentes/indexdoc.html', mensaje='codigo repetido')
        elif existe_doc(ci_docente):
        # Almacenar en la base de datos
            conn =  sqlite3.connect("kronos.db")
            cursor = conn.cursor()
            cursor.execute("INSERT INTO curso(codigo,nombre,descripcion,ci_docente) VALUES (?,?,?,?)",(codigo,nombre,descripcion,ci_docente))
            conn.commit()
            conn.close()
        else:
            return render_template('', mensaje='docente no encontrado')
    return render_template('docentes/indexdoc.html',mensaje='registrado')

#ruta registrar admin
@app.route("/registraradm",methods=['GET','POST'])
def regadm():
    if request.method == 'POST':
        ci_adm =  request.form['ci_adm']
        nombre =  request.form['nombre']
        username = request.form['username']
        password = request.form['password']
        if (existe(ci_adm) or existe_doc(ci_adm) or existe_adm(ci_adm)):
            return render_template('admin/registraradmi.html', mensaje='el numero de carnet ya se encuentra registrado.')
        else:
            if (existeusuario(username) or existeusuariodoc(username) or existeusuarioadm(username)):
                return render_template('admin/registraradmi.html', mensaje='el nombre de usuario ya existe.')
            else:
        # Encriptar el password
                password_encriptado =  generate_password_hash(password)
        # Almacenar en la base de datos
                conn =  sqlite3.connect("kronos.db")
                cursor = conn.cursor()
                cursor.execute("INSERT INTO admin(ci_adm,nombre,username,password) VALUES (?,?,?,?)",(ci_adm,nombre,username,password_encriptado))
                conn.commit()
                conn.close()
                return render_template('admin/registraradmi.html',mensaje='registrado')
    return render_template('admin/dashboard.html')

@app.route("/registerpago",methods=['GET','POST'])
def regpago():
    if request.method == 'POST':
        curso =  request.form['curso']
        carnet =  request.form['carnet']
        detalle = request.form['detalle']
        # Almacenar en la base de datos
        conn =  sqlite3.connect("kronos.db")
        cursor = conn.cursor()
        cursor.execute("INSERT INTO recorrido (curso,carnet_es,detalle) VALUES (?,?,?)",(curso,carnet,detalle))
        conn.commit()
        conn.close()
        return render_template('pagos.html')
    return render_template('auth/login.html')

#ruta salir
@app.route("/logout")
def logout():
    session.pop('user_id',None)
    return redirect("/")

#ruta administrador
@app.route("/admin/dashboard")
@login_required
def dashboard():
    return render_template('admin/dashboard.html')

#ruta registro administrador
@app.route("/admin/registroadm")
def docentes():
    return render_template('admin/registraradmi.html')

#ruta eliminar datos usuario
@app.route('/borrar/<int:carnet>', methods=['POST']) 
def borrar_dato(carnet): 
    conn = sqlite3.connect('kronos.db') 
    cursor = conn.cursor() 
    cursor.execute('DELETE FROM usuarios WHERE carnet= ?', (carnet,)) 
    conn.commit() 
    conn.close() 
    return redirect(url_for('mostrar_datos'))

#ruta eliminar datos doc
@app.route('/borrardoc/<int:carnet>', methods=['POST']) 
def borrar_datodoc(carnet): 
    conn = sqlite3.connect('kronos.db') 
    cursor = conn.cursor() 
    cursor.execute('DELETE FROM docente WHERE carnet_doc= ?', (carnet,)) 
    conn.commit() 
    conn.close() 
    return redirect(url_for('mostrar_datos'))

#ruta eliminar datos curso
@app.route('/borrarcur/<int:carnet>', methods=['POST']) 
def borrar_datocur(carnet): 
    conn = sqlite3.connect('kronos.db') 
    cursor = conn.cursor() 
    cursor.execute('DELETE FROM curso WHERE codigo= ?', (carnet,)) 
    conn.commit() 
    conn.close() 
    return redirect(url_for('mostrar_datos'))

#ruta eliminar datos curso
@app.route('/borraradm/<int:carnet>', methods=['POST']) 
def borrar_datoadm(carnet): 
    conn = sqlite3.connect('kronos.db') 
    cursor = conn.cursor() 
    cursor.execute('DELETE FROM admin WHERE ci_adm= ?', (carnet,)) 
    conn.commit() 
    conn.close() 
    return redirect(url_for('mostrar_datos'))

#ruta mostrar datos administrador
@app.route('/admin/datos')
@login_required
def mostrar_datos():
    datos_cur=obtener_curso()
    datos = obtener_datos()
    datos_doc=obtener_doc()
    dato_adm=obtener_adm()
    return render_template('admin/datos.html', usuarios=datos,curs=datos_cur,doce=datos_doc,adm=dato_adm)

#funcion obtener datos usuario
def obtener_datos():
    conn = sqlite3.connect('kronos.db')
    cursor = conn.cursor()
    cursor.execute('SELECT carnet, nombre, apellido, username FROM usuarios')
    datos = cursor.fetchall()
    conn.close()
    return datos

#funcion obtener datos curso
def obtener_curso():
    conn = sqlite3.connect('kronos.db')
    cursor = conn.cursor()
    cursor.execute('SELECT codigo, nombre, descripcion,ci_docente FROM curso')
    datos = cursor.fetchall()
    conn.close()
    return datos

#funcion obtener datos docente
def obtener_doc():
    conn = sqlite3.connect('kronos.db')
    cursor = conn.cursor()
    cursor.execute('SELECT carnet_doc,nombre,apellido,titulo,username FROM docente')
    datos = cursor.fetchall()
    conn.close()
    return datos

#funcion obtener datos administrador
def obtener_adm():
    conn = sqlite3.connect('kronos.db')
    cursor = conn.cursor()
    cursor.execute('SELECT ci_adm, nombre, username FROM admin')
    datos = cursor.fetchall()
    conn.close()
    return datos

#funcion obtener datos administrador
def obtener_prog():
    conn = sqlite3.connect('kronos.db')
    cursor = conn.cursor()
    cursor.execute('SELECT id, curso, carnet_es, detalle FROM recorrido')
    datos = cursor.fetchall()
    conn.close()
    return datos

#ruta index
@app.route("/ret")
@login_required
def ret():
    da=obtener_curso()
    return render_template('index.html',dacursos=da)

#ruta listacurso
@app.route("/cur")
@login_required
def retcu():
    da=obtener_curso()
    return render_template('pagos.html',dasc=da)

#ruta docente
@app.route("/docentes/inicio")
@login_required
def retdoc():
    return render_template('/docentes/indexdoc.html')

#ruta progreso
@app.route("/prog")
@login_required
def prog():
    da=obtener_prog()
    return render_template('progreso.html',daprog=da)

#ruta detalle curso
@app.route('/detalle/<int:codigo>')
def ver_dato(codigo):
    conn = sqlite3.connect('kronos.db') 
    conn.row_factory =  sqlite3.Row
    cursor = conn.execute('SELECT * FROM curso WHERE codigo = ?', (codigo,))
    envio = cursor.fetchone()
    doc = conn.execute('SELECT ci_docente FROM curso WHERE codigo = ?', (codigo,))
    ci_docente = doc.fetchone()['ci_docente']
    aux1 = conn.execute('SELECT * FROM docente WHERE carnet_doc = ?', (ci_docente,))
    dato_doc = aux1.fetchone()
    conn.close()
    return render_template('cursos.html', ecod=envio, d_doc=dato_doc)


if __name__ == "__main__":
    app.run(debug=True)

