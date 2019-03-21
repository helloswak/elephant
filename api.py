from flask import Flask, jsonify, request
from flask_sqlalchemy import SQLAlchemy
from flask_cors import CORS
from flask_jwt_extended import (
    JWTManager, jwt_required, create_access_token,
    jwt_refresh_token_required, create_refresh_token,
    get_jwt_identity
)
from os import environ
from datetime import datetime
from passlib.hash import sha512_crypt

app = Flask(__name__)
cors = CORS(app, resources={r"/api/v1/*": {"origins": "*"}})

app.config['SQLALCHEMY_DATABASE_URI'] = environ.get('DATABASE_URL')
app.config['SECRET_KEY'] = 'I_LOVE_APPLE-STEVE_JOBS-1976_2011'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = True

db = SQLAlchemy(app)
jwt = JWTManager(app)


@app.before_first_request
def create_tables():
    db.create_all()

class User(db.Model):
    __tablename__ = "user"
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(42), unique=True, nullable=False)
    password = db.Column(db.String(255), nullable=False)

    @classmethod
    def find_by_username(cls, username):
        return cls.query.filter_by(username=username).first()

    def save_to_db(self):
        db.session.add(self)
        db.session.commit()

    @staticmethod
    def generate_hash(password):
        return sha512_crypt.hash(password)

    @staticmethod
    def verify_hash(password, hash):
        return sha512_crypt.verify(password, hash)


@app.route('/')
def hello():
    return jsonify({'message': 'One more thing...'}), 201


@app.route('/registration', methods=['POST'])
def registration():
        data = request.get_json()
        current_user = User.find_by_username(data['username'])

        if current_user:
            ret = {
                'message': 'user found'
            }
            return jsonify(ret), 201

        new_user = User()
        new_user.username = data['username']
        new_user.password = User.generate_hash(data['password'])

        try:
            new_user.save_to_db()
            ret = {
                'access_toke': create_access_token(identity=data['username']),
                'refresh_token': create_refresh_token(identity=data['username'])
            }
            return jsonify(ret), 200

        except Exception as e:
            print(e)
            return {'message', 'Something went wrong'}, 500


@app.route('/login', methods=['POST'])
def login():
    data = request.get_json()
    current_user = User.find_by_username(data['username'])

    if not current_user:
        ret = {
            'code': '50', 
            'message': 'user not found'
        }
        return jsonify(ret), 401

    if User.verify_hash(data['password'], current_user.password):
        ret = {
            'access_toke': create_access_token(identity=data['username']),
            'refresh_token': create_refresh_token(identity=data['username'])
        }
        return jsonify(ret), 200

    else:
        ret = {
            'code': '51', 
            'message': 'Bad password'
        }
        return jsonify(ret), 401


@app.route('/password/forget', methods=['GET'])
def password_forget():
    data = request.get_json()

    current_user = User.find_by_username(data['username'])
    if current_user:
        return 200
    return 401


@app.route('/token/refresh', methods=['POST'])
@jwt_refresh_token_required
def refresh():
    current_user = get_jwt_identity()
    ret = {
        'access_token': create_access_token(identity=current_user)
    }
    return jsonify(ret), 200


@app.route('/feed', methods=['GET'])
@jwt_required
def protected():
    username = get_jwt_identity()
    return jsonify(logged_in_as=username), 200

