# app.py
import os
from flask_mail import Mail, Message
from itsdangerous import URLSafeTimedSerializer
from flask import Flask, request, jsonify
from flask_sqlalchemy import SQLAlchemy
from flask_bcrypt import Bcrypt
from flask_cors import CORS
import jwt
from datetime import datetime, timedelta
from functools import wraps
from dotenv import load_dotenv
load_dotenv()

# Inicialización de la aplicación
app = Flask(__name__)
CORS(app)

# Configuración CORS más robusta para permitir el header de autorización
CORS(app, resources={r"/*": {"origins": "*"}}, supports_credentials=True, allow_headers=["Content-Type", "Authorization"])

# Configuración de base de datos
DATABASE_URL = os.getenv("DATABASE_URL")

if DATABASE_URL and DATABASE_URL.startswith("postgres://"):
    DATABASE_URL = DATABASE_URL.replace("postgres://", "postgresql://", 1)

app.config["SQLALCHEMY_DATABASE_URI"] = DATABASE_URL or "sqlite:///local.db"
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False

db = SQLAlchemy(app)
bcrypt = Bcrypt(app)

# ----------------------------------------------------
# Modelos de la Base de Datos
# Se han actualizado los modelos a la versión que proporcionaste.
# ----------------------------------------------------

def send_reset_email(user_email, token):
    reset_url = f"http://localhost:3000/reset-password/{token}"

    html_body = f"""
    <html>
    <body style="font-family: Arial, sans-serif; background-color:#f6f9f8; padding:20px;">
      <table align="center" cellpadding="0" cellspacing="0" width="600" style="background:white; border-radius:10px; box-shadow:0 2px 10px rgba(0,0,0,.1);">
        <tr>
          <td align="center" style="padding:20px; background-color:#00b09b; border-radius:10px 10px 0 0;">
            <img src="https://i.imgur.com/2PqQ1qv.png" alt="Saviare Logo" width="120" />
            <h2 style="color:white; margin:10px 0;">Plataforma Saviare</h2>
          </td>
        </tr>
        <tr>
          <td style="padding:30px;">
            <p style="font-size:16px; color:#333;">Hola,</p>
            <p style="font-size:16px; color:#333;">Recibimos una solicitud para restablecer tu contraseña.</p>
            <p style="text-align:center;">
              <a href="{reset_url}" style="display:inline-block; background-color:#00b09b; color:white; padding:12px 24px; border-radius:8px; text-decoration:none; font-weight:bold;">Restablecer Contraseña</a>
            </p>
            <p style="font-size:14px; color:#666;">Si tú no solicitaste este cambio, puedes ignorar este mensaje. Tu contraseña seguirá siendo la misma.</p>
          </td>
        </tr>
        <tr>
          <td align="center" style="background-color:#f0f0f0; border-radius:0 0 10px 10px; padding:15px;">
            <p style="font-size:12px; color:#666;">© 2025 Saviare LTDA · Todos los derechos reservados.</p>
          </td>
        </tr>
      </table>
    </body>
    </html>
    """

    msg = Message('🔒 Recuperación de Contraseña – Saviare',
                  recipients=[user_email],
                  html=html_body)
    mail.send(msg)

class Users(db.Model):
    __tablename__ = 'users'
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password = db.Column(db.String(255), nullable=False)
    role = db.Column(db.String(20), nullable=False, default='estudiante')
    # Relación con Courses
    courses = db.relationship('Courses', backref='instructor_rel', lazy=True)

class Courses(db.Model):
    __tablename__ = 'courses'
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(100), nullable=False)
    description = db.Column(db.Text, nullable=False)
    instructor = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)

# ----------------------------------------------------
# Middleware de Autenticación
# Se utiliza el decorador que proporcionaste para la validación del token.
# ----------------------------------------------------

def token_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = None
        # Intenta obtener el token del encabezado 'Authorization'
        if 'Authorization' in request.headers:
            token = request.headers['Authorization'].split(" ")[1]

        if not token:
            return jsonify({'message': 'Token de autenticación faltante o inválido'}), 401

        try:
            # Decodifica el token con la clave secreta
            data = jwt.decode(token, app.config['SECRET_KEY'], algorithms=["HS256"])
            current_user = Users.query.filter_by(id=data['user_id']).first()
        except jwt.ExpiredSignatureError:
            print("Token expirado.")
            return jsonify({'message': 'Token expirado. Por favor, vuelva a iniciar sesión.'}), 401
        except jwt.InvalidTokenError:
            print("Token inválido.")
            return jsonify({'message': 'Token inválido. Por favor, vuelva a iniciar sesión.'}), 401
        
        return f(current_user, *args, **kwargs)

    return decorated

# ----------------------------------------------------
# Rutas de la API
# Se han actualizado las rutas y la lógica de login y obtención de cursos.
# ----------------------------------------------------

@app.route('/')
def home():
    return jsonify({"mensaje": "¡Bienvenido a la API de Saviare!"})

@app.route('/register', methods=['POST'])
def register():
    username = request.json.get('username', None)
    password = request.json.get('password', None)
    role = request.json.get('role', 'estudiante')

    if not username or not password:
        return jsonify({"msg": "Faltan usuario y contraseña"}), 400
    
    if Users.query.filter_by(username=username).first():
        return jsonify({"msg": "El usuario ya existe"}), 409
    
    hashed_password = bcrypt.generate_password_hash(password).decode('utf-8')
    new_user = Users(username=username, password=hashed_password, role=role)
    db.session.add(new_user)
    db.session.commit()
    return jsonify({"msg": f"Usuario {username} registrado exitosamente como {role}"}), 201

@app.route('/login', methods=['POST'])
def login():
    username = request.json.get('username', None)
    password = request.json.get('password', None)
    
    user = Users.query.filter_by(username=username).first()
    
    if user and bcrypt.check_password_hash(user.password, password):
        # Creamos un token JWT manualmente con el ID del usuario
        token = jwt.encode({
            'user_id': user.id,
            'exp': datetime.utcnow() + timedelta(minutes=15) # Token expira en 15 minutos
        }, app.config['SECRET_KEY'], algorithm="HS256")
        print(f"Login exitoso para: {username}. Token creado.")
        return jsonify({'access_token': token})
    else:
        print(f"Fallo de login para: {username}.")
        return jsonify({"msg": "Credenciales inválidas"}), 401

@app.route('/courses', methods=['GET'])
@token_required
def get_courses(current_user):
    courses = Courses.query.all()
    output = []
    for course in courses:
        output.append({
            'id': course.id,
            'title': course.title,
            'description': course.description,
            'instructor': course.instructor_rel.username
        })
    print(f"Acceso a cursos autorizado para el usuario {current_user.username}. Se enviaron {len(courses)} cursos.")
    # El frontend de React espera un array directo, no un objeto anidado.
    return jsonify(output)

# ----------------------------------------------------
# Inicialización de la Base de Datos y Datos de Prueba
# ----------------------------------------------------

def setup_database_and_data():
    with app.app_context():
        db.create_all()
        # Verificar si ya existe un instructor para evitar duplicados
        if not Users.query.filter_by(username='profe_saviare').first():
            hashed_password_profe = bcrypt.generate_password_hash('profe123').decode('utf-8')
            user_profe = Users(username='profe_saviare', password=hashed_password_profe, role='instructor')
            db.session.add(user_profe)
            db.session.commit()
            print("Usuario instructor de prueba creado.")

        # Verificar si ya existen cursos para evitar duplicados
        if not Courses.query.first():
            user_profe = Users.query.filter_by(username='profe_saviare').first()
            if user_profe:
                course1 = Courses(title='Introducción a la Seguridad Operacional', description='Conoce los fundamentos de la gestión de la seguridad en la aviación.', instructor=user_profe.id)
                course2 = Courses(title='Factores Humanos en la Aviación', description='Analiza cómo la conducta humana impacta en la seguridad de las operaciones.', instructor=user_profe.id)
                course3 = Courses(title='Gestión de Riesgos Aeronáuticos', description='Aprende a identificar, evaluar y mitigar los riesgos en el entorno aéreo.', instructor=user_profe.id)
                db.session.add(course1)
                db.session.add(course2)
                db.session.add(course3)
                db.session.commit()
                print("Cursos de prueba creados.")

@app.route('/forgot-password', methods=['POST'])
def forgot_password():
    data = request.json
    username = data.get('username')

    user = Users.query.filter_by(username=username).first()
    if not user:
        return jsonify({"msg": "Usuario no encontrado"}), 404

    # Crear token de recuperación
    token = serializer.dumps(user.username, salt='password-reset-salt')

    reset_link = f"http://localhost:5173/reset-password/{token}"

    msg = Message(
        subject="🔐 Recupera tu contraseña - Centro Educativo Saviare",
        recipients=[user.username],  # Asumiendo que el username es un correo
        body=f"Hola, {user.username}.\n\nPara restablecer tu contraseña, haz clic en el siguiente enlace:\n{reset_link}\n\nEste enlace expirará en 15 minutos."
    )

    mail.send(msg)
    print(f"Correo de recuperación enviado a {user.username}")

    return jsonify({"msg": "Correo de recuperación enviado. Revisa tu bandeja de entrada."})

@app.route('/reset-password/<token>', methods=['POST'])
def reset_password(token):
    try:
        username = serializer.loads(token, salt='password-reset-salt', max_age=900)  # 15 minutos
    except Exception:
        return jsonify({"msg": "El enlace ha expirado o es inválido"}), 400

    data = request.json
    new_password = data.get('password')

    user = Users.query.filter_by(username=username).first()
    if not user:
        return jsonify({"msg": "Usuario no encontrado"}), 404

    hashed_password = bcrypt.generate_password_hash(new_password).decode('utf-8')
    user.password = hashed_password
    db.session.commit()

    return jsonify({"msg": "Contraseña actualizada correctamente."})


if __name__ == '__main__':
    setup_database_and_data()
    app.run(debug=True)
