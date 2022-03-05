from flask import Flask, request, jsonify, make_response
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
from functools import wraps
import datetime
import uuid
import jwt

app = Flask(__name__)

app.config['SECRET_KEY'] = 'thisisasecretkey'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///users.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db = SQLAlchemy(app)


class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.String(50), unique=True)
    username = db.Column(db.String(50), unique=True)
    password = db.Column(db.String(100))
    admin = db.Column(db.Boolean())


def token_required(fn):
    @wraps(fn)
    def decorated(*args, **kwargs):
        token = None

        if 'x-access-token' in request.headers:
            token = request.headers['x-access-token']

        if not token:
            return jsonify({'message': 'Unauthorized'}), 401

        try:
            data = jwt.decode(
                token, app.config['SECRET_KEY'], algorithms=['HS256'])

            current_user = User.query.filter_by(
                user_id=data['user_id']).first()
        except:
            return jsonify({'message': 'Unauthorized'}), 401

        return fn(current_user, *args, **kwargs)

    return decorated


@app.route('/users', methods=['GET'])
@token_required
def get_all_users(current_user):
    if not current_user.admin:
        return jsonify({'message': 'Access denied.'}), 403

    users = User.query.all()
    output = []

    for user in users:
        user_data = {}
        user_data['user_id'] = user.user_id
        user_data['username'] = user.username
        user_data['admin'] = user.admin
        output.append(user_data)

    return jsonify({'data': output})


@app.route('/users/<user_id>', methods=['GET'])
@token_required
def get_single_user(current_user, user_id):
    if not current_user.admin:
        return jsonify({'message': 'Access denied.'}), 403

    user = User.query.filter_by(user_id=user_id).first()

    if not user:
        return jsonify({'message': 'No user found'}), 404

    user_data = {}
    user_data['user_id'] = user.user_id
    user_data['username'] = user.username
    user_data['admin'] = user.admin

    return jsonify({'data': user_data})


@app.route('/users/<user_id>', methods=['PUT'])
@token_required
def promote_user(current_user, user_id):
    if not current_user.admin:
        return jsonify({'message': 'Access denied.'}), 403

    user = User.query.filter_by(user_id=user_id).first()

    if not user:
        return jsonify({'message': 'No user found.'}), 404

    user.admin = True
    db.session.commit()

    return jsonify({'message': 'The user has been promoted.'}), 204


@app.route('/users/<user_id>', methods=['DELETE'])
@token_required
def delete_user(current_user, user_id):
    if not current_user.admin:
        return jsonify({'message': 'Access denied.'}), 403

    user = User.query.filter_by(user_id=user_id).first()

    if not user:
        return jsonify({'message': 'No user found.'}), 404

    db.session.delete(user)
    db.session.commit()

    return jsonify({'message': 'The user has been deleted.'}), 204


@app.route('/users', methods=['POST'])
def register_user():
    data = request.get_json()
    hashed_password = generate_password_hash(
        data['password'], method='pbkdf2:sha256', salt_length=8)

    new_user = User(user_id=str(uuid.uuid4()),
                    username=data['username'], password=hashed_password, admin=False)
    db.session.add(new_user)
    db.session.commit()

    return jsonify({'message': 'New user has been created.'}), 201


@app.route('/login', methods=['POST'])
def login_user():
    auth = request.authorization

    if not auth or not auth.username or not auth.password:
        return make_response('Invalid credentials.', 401, {'WWW-Authenticate': 'Basic realm="Login Required!"'})

    user = User.query.filter_by(username=auth.username).first()

    if not user:
        return make_response('Invalid credentials.', 401, {'WWW-Authenticate': 'Basic realm="Login Required!"'})

    if check_password_hash(user.password, auth.password):
        token = jwt.encode({'user_id': user.user_id, 'exp': datetime.datetime.utcnow(
        ) + datetime.timedelta(minutes=30)}, app.config['SECRET_KEY'], algorithm='HS256')

        return jsonify({'token': token})

    return make_response('Invalid credentials.', 401, {'WWW-Authenticate': 'Basic realm="Login Required!"'})


if __name__ == '__main__':
    app.run(debug=True)
