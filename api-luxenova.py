from flask import Flask, request, jsonify, session
from flask_sqlalchemy import SQLAlchemy
from flask_cors import CORS
from flask_session import Session  # Importa flask-session para manejo de sesiones

app = Flask(__name__)
CORS(app)

# Configura la base de datos y la sesión
app.config['SQLALCHEMY_DATABASE_URI'] = 'mysql+pymysql://admin:O-nt6051{fv@proyectoluxenova.cfsgec4e46so.us-east-1.rds.amazonaws.com/luxenova'

app.config['SECRET_KEY'] = 'your_secret_key'  # Clave secreta para la sesión, cámbiala en producción
app.config['SESSION_TYPE'] = 'filesystem'  # Almacena las sesiones en el sistema de archivos local

# Inicializa las extensiones
db = SQLAlchemy(app)
Session(app)

# Define las tablas y modelos
class User(db.Model):
    __tablename__ = 'users'
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(255), unique=True, nullable=False)
    phone = db.Column(db.String(20), unique=True, nullable=False)
    password = db.Column(db.String(255), nullable=False)
    first_name = db.Column(db.String(50), nullable=False)
    last_name = db.Column(db.String(50), nullable=False)
    created_at = db.Column(db.TIMESTAMP, default=db.func.current_timestamp())
    updated_at = db.Column(db.TIMESTAMP, default=db.func.current_timestamp(), onupdate=db.func.current_timestamp())
    roles = db.relationship('UserRole', backref='user', lazy=True)

class UserRole(db.Model):
    __tablename__ = 'user_roles'
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    role = db.Column(db.Enum('owner', 'admin', 'customer'), nullable=False)
    created_at = db.Column(db.TIMESTAMP, default=db.func.current_timestamp())
    updated_at = db.Column(db.TIMESTAMP, default=db.func.current_timestamp(), onupdate=db.func.current_timestamp())

# Ruta de login que crea una sesión si las credenciales son correctas
@app.route('/login', methods=['POST'])
def login():
    data = request.json
    email = data.get('email')
    password = data.get('password')
    user = User.query.filter_by(email=email).first()

    if user and user.password == password:
        # Obtener el rol del usuario
        user_role = UserRole.query.filter_by(user_id=user.id).first()
        role = user_role.role if user_role else 'No role assigned'

        # Crear sesión con los datos del usuario
        session['user_id'] = user.id
        session['email'] = user.email
        session['role'] = role

        return jsonify({
            'message': 'Login successful',
            'user': {
                'email': user.email,
                'first_name': user.first_name,
                'last_name': user.last_name,
            },
            'role': role
        }), 200
    else:
        return jsonify({'message': 'Invalid credentials'}), 401

# Ruta de logout para destruir la sesión
@app.route('/logout', methods=['POST'])
def logout():
    session.clear()  # Elimina todos los datos de la sesión
    return jsonify({'message': 'Logout successful'}), 200

# Ruta protegida de ejemplo que requiere sesión activa
@app.route('/protected', methods=['GET'])
def protected():
    if 'user_id' in session:
        return jsonify({'message': 'This is a protected route', 'user': session['email'], 'role': session['role']}), 200
    else:
        return jsonify({'message': 'Unauthorized access'}), 401

if __name__ == '__main__':
    app.run(debug=True)
