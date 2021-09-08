#!/usr/bin/python3
# Author:   @AgbaD || @agba_dr3

from werkzeug.security import generate_password_hash, check_password_hash
from flask import Flask, request, jsonify
from flask_pymongo import PyMongo
from flask_sslify import SSLify
from dotenv import load_dotenv
from flask_cors import CORS
import jwt

import os
import uuid
from functools import wraps
from datetime import datetime, timedelta

from schema import validate_login, validate_reg, validate_user_db


load_dotenv()
app = Flask(__name__)

# db
password = os.getenv('PASSWORD')
database = "Dotes"
url = f'mongodb+srv://asteroid:{password}@cluster0.ppcp1.mongodb.net/{database}?retryWrites=true&w=majority'

# Configurations
app.config['SECRET_KEY'] = os.getenv('SECRET_KEY')
app.config['MONGO_URI'] = url
app.config['SSL_DISABLE'] = False

mongo = PyMongo(app)
CORS(app)

workspaces = mongo.db.workspaces
users = mongo.db.users


if not app.debug and not app.testing and not app.config['SSL_DISABLE']:
    sslify = SSLify(app)


def token_optional(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = None

        if 'x-access_token' in request.headers:
            token = request.headers['x-access_token']

        if not token:
            return f(user=None, *args, **kwargs)

        try:
            data = jwt.decode(token, app.config['SECRET_KEY'], algorithms=['HS256'])
            user = users.find_one({'public_id': data['public_id']})
            if user:
                return f(user=user, *args, **kwargs)
            return f(user=None, *args, **kwargs)
        except Exception:
            return f(user=None, *args, **kwargs)
    return decorated


def token_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = None

        if 'x-access-token' in request.headers:
            token = request.headers['x-access-token']
        if not token:
            return jsonify({
                'status': 'error',
                'message': "Token is missing"
            }), 401

        try:
            data = jwt.decode(token, app.config['SECRET_KEY'], algorithms=['HS256'])
            current_user = users.find_one({'public_id': data['public_id']})

        except Exception:
            return jsonify({
                'status': 'error',
                'message': "Token is invalid"
            }), 401

        return f(current_user, *args, **kwargs)
    return decorated


@app.route('/')
def index():
    return "You are connected!"


@app.route('/login', methods=['POST'])
def login():
    """
    required
        $curl -X POST /login
        -d '{
            "email": "example@example.com",
            "password": "xxxxxx"
        }'
    :return: {
        'status': 'success',
        'message': "Login successful",
        'data': {
            'token': token
        }
    }
    """
    if request.method == "POST":
        try:
            data = request.get_json()

            email = data['email'].lower()
            password = data['password']

            user_data = {
                "email": email,
                "password": password
            }

            schema = validate_login(user_data)
            if schema['msg'] == "error":
                return jsonify({
                    'status': 'error',
                    'message': schema['error']
                }), 400

            user = users.find_one({'email': email})
            if not user:
                return jsonify({
                    'status': 'error',
                    'message': "Invalid email or password."
                }), 400

            if check_password_hash(user['password'], password):
                token = jwt.encode({
                    'public_id': user['public_id'],
                    'exp': datetime.utcnow() + timedelta(minutes=30)
                }, app.config['SECRET_KEY'], "HS256")

                return jsonify({
                    'status': 'success',
                    'message': "Login successful",
                    'data': {
                        'token': token
                    }
                }), 200
            else:
                return jsonify({
                    'status': 'error',
                    'message': "Invalid email or password."
                }), 400
        except Exception as e:
            return jsonify({
                'status': 'error',
                'message': e
            }), 500
    else:
        return jsonify({
            'status': 'error',
            'message': "Endpoint does not support {} requests".format(request.method)
        }), 400


@app.route('/register', methods=['POST'])
@token_optional
def register(user):
    """
    required
        $curl -X POST /register
        -d '{
            "email": "example@example.com",
            "password": "xxxxxx",
            "repeat_password": "xxxxxx",
            "fullname": "John Doe",
            "workspace": "workspace name"   // if user, user workspace must == workspace
        }'
    optional
        -H '{"x-access-token": token}'

    :param user: // if x-access-token in header && token is_valid, pass user to endpoint
            // else, pass None

    :return: {
        'status': 'success',
        'message': "User registration successful"
    }
    """
    if request.method == "POST":
        try:
            data = request.get_json()

            email = data['email'].lower()
            password = data['password']
            repeat_password = data['repeat_password']
            fullname = data['fullname']
            workspace = str(data['workspace'])

            if user:
                if not user['is_admin']:
                    return jsonify({
                        'status': 'error',
                        'message': 'Forbidden for users without full privileges'
                    }), 403

            # to be removed later
            if users.find_one({'email': email}):
                return jsonify({
                    'status': 'error',
                    'message': 'Email has been used'
                }), 400

            if password != repeat_password:
                return jsonify({
                    'status': 'error',
                    'message': 'Passwords do not match'
                }), 400

            info = {
                "fullname": fullname,
                "email": email,
                "password": password,
                "workspace": workspace
            }

            schema = validate_reg(info)
            if schema['msg'] != "success":
                return jsonify({
                    'status': 'error',
                    'message': schema['error']
                }), 400

            if workspaces.find_one({'name': workspace}):
                if user and user['workspace'] == workspace:
                    pass
                elif user and user['workspace'] != workspace:
                    return jsonify({
                        'status': 'error',
                        'message': f'Forbidden. You are not authorized to add user to workspace {workspace}'
                    }), 403
                else:
                    return jsonify({
                        'status': 'error',
                        'message': 'workspace name has been used. Choose unique name'
                    }), 400
            else:
                workspaces.insert_one({'name': workspace})

            password_hash = generate_password_hash(password)
            admin = False
            if not user:
                admin = True

            public_id = str(uuid.uuid4())
            while users.find_one({'public_id': public_id}):
                public_id = str(uuid.uuid4())

            new_user = {
                "email": email,
                "fullname": fullname,
                "password": password_hash,
                "public_id": public_id,
                "workspace": workspace,
                "is_admin": admin
            }

            schema = validate_user_db(new_user)
            if schema['msg'] != "success":
                return jsonify({
                    'status': 'error',
                    'message': schema['error']
                }), 400
            users.insert_one(new_user)
            return jsonify({
                'status': 'success',
                'message': "User registration successful"
            }), 201

        except Exception as e:
            return jsonify({
                'status': 'error',
                'message': e
            }), 500
    else:
        return jsonify({
            'status': 'error',
            'message': "Endpoint does not support {} requests".format(request.method)
        }), 400


@app.route('/update_password', methods=['PUT', 'POST'])
@token_required
def update_password(current_user):
    """
    required
        $curl -X POST|PUT /update_password
        -H '{"x-access-token": token}'
        -d '{
            "password": "xxxxxx",
            "repeat_password": "xxxxxx",
        }'

    :param current_user: // if x-access-token in header && token is_valid, pass user to endpoint
            // else, return error as response
    :return: {
        'status': 'success',
        'message': "Password update successful"
    }
    """
    if request.method == "PUT" or request.method == "POST":
        try:
            data = request.get_json()

            password = data['password']
            repeat_password = data['repeat_password']

            if password != repeat_password:
                return jsonify({
                    'status': 'error',
                    'message': 'Passwords do not match'
                }), 400

            password_hash = generate_password_hash(password)
            public_id = current_user['public_id']
            users.update_one(
                {'public_id': public_id},
                {'$set': {'password': password_hash}}
            )
            return jsonify({
                'status': 'success',
                'message': "Password update successful"
            }), 200
        except Exception as e:
            return jsonify({
                'status': 'error',
                'message': e
            }), 500
    else:
        return jsonify({
            'status': 'error',
            'message': "Endpoint does not support {} requests".format(request.method)
        }), 400


@app.route('/profile', methods=['GET'])
@token_required
def profile(current_user):
    """
    required
        $curl -X GET /profile
        -H '{"x-access-token": token}'

    :param current_user: // if x-access-token in header && token is_valid, pass user to endpoint
            // else, return error as response
    :return: {
        'status': 'success',
        'data': {
            'user_details': data
        }
    }
    """
    if request.method == 'GET':
        try:
            data = {
                'email': current_user['email'],
                'fullname': current_user['fullname'],
                'workspace': current_user['workspace'],
                'is_admin': current_user['is_admin'],
                'public_id': current_user['public_id']
            }

            return jsonify({
                'status': 'success',
                'data': {
                    'user_details': data
                }
            }), 200
        except Exception as e:
            return jsonify({
                'status': 'error',
                'message': e
            }), 500
    else:
        return jsonify({
            'status': 'error',
            'message': "Endpoint does not support {} requests".format(request.method)
        }), 400


@app.route('/get_all_users', methods=['GET'])
@token_required
def get_all_users(current_user):
    """
    required
        $curl -X GET /get_all_users
        -H '{"x-access-token": token}'

    :param current_user: // if x-access-token in header && token is_valid, pass user to endpoint
            // else, return error as response
    :return: {
        'status': 'success',
        'data': {
            'all_users': all_users
        }
    }
    """
    if request.method == 'GET':
        try:
            workspace = current_user['workspace']
            db_users = users.find({'workspace': workspace})

            all_users = []
            for user in db_users:
                data = {
                    'email': user['email'],
                    'fullname': user['fullname'],
                    'workspace': user['workspace'],
                    'is_admin': user['is_admin'],
                    'public_id': user['public_id']
                }
                all_users.append(data)

            return jsonify({
                'status': 'success',
                'data': {
                    'all_users': all_users
                }
            }), 200
        except Exception as e:
            return jsonify({
                'status': 'error',
                'message': e
            }), 500
    else:
        return jsonify({
            'status': 'error',
            'message': "Endpoint does not support {} requests".format(request.method)
        }), 400


@app.route('/update_user/<user_email>', methods=['PUT', 'POST'])
@token_required
def update_user(current_user, user_email):
    """
    required
        $curl -X POST|PUT /update_user/<user_email>
        -H '{"x-access-token": token}'
        -d '{
            "password": "xxxxxx",
            "email": "example@email.com",
            "fullname": "John Doe"
        }'  // at least one of these 3

    :param current_user: // if x-access-token in header && token is_valid, pass user to endpoint
            // else, return error as response

    :param user_email: // email of user to be updated
    :return: {
        'status': 'success',
        'message': "User update successful"
    }
    """
    if request.method == "PUT" or request.method == "POST":
        try:
            if not current_user['is_admin']:
                return jsonify({
                    'status': 'error',
                    'message': 'Forbidden for users without full privileges'
                }), 403

            data = request.get_json()
            if not data['email'] or data["fullname"] or data["password"]:
                return jsonify({
                    'status': 'error',
                    'message': "Invalid Credentials"
                }), 400

            user = users.find_one({'email': user_email})
            if not user:
                return jsonify({
                    'status': 'error',
                    'message': "User not found"
                }), 404

            if user['workspace'] != current_user['workspace']:
                return jsonify({
                    'status': 'error',
                    'message': "Action forbidden! Cannot edit user in another workspace"
                }), 403

            new_data = {}
            if data['email']:
                new_data['email'] = data['email']
            if data["fullname"]:
                new_data['fullname'] = data["fullname"]
            if data["password"]:
                password = data["password"]
                repeat_password = data["repeat_password"]

                if password != repeat_password:
                    return jsonify({
                        'status': 'error',
                        'message': 'Passwords do not match'
                    }), 401
                new_data['password'] = data["password"]
            users.update_one(
                {'email': user_email},
                {'$set': new_data}
            )
            return jsonify({
                'status': 'success',
                'message': "User update successful"
            }), 200

        except Exception as e:
            return jsonify({
                'status': 'error',
                'message': e
            }), 500
    else:
        return jsonify({
            'status': 'error',
            'message': "Endpoint does not support {} requests".format(request.method)
        }), 400


@app.route("/delete_user/<user_email>", methods=['DELETE'])
@token_required
def delete_user(current_user, user_email):
    """
    required
        $curl -X DELETE /delete_user/<user_email>
        -H '{"x-access-token": token}'

    :param current_user: // if x-access-token in header && token is_valid, pass user to endpoint
            // else, return error as response
    :param user_email: // email of user to be deleted
    :return: {
        'status': 'success',
        'message': "User removed successfully"
    }
    """
    if not current_user['is_admin']:
        return jsonify({
            'status': 'error',
            'message': 'Forbidden for users without full privileges'
        }), 403

    user = users.find_one({'email': user_email})
    if not user:
        return jsonify({
            'status': 'error',
            'message': "User not found"
        }), 404

    if user['workspace'] != current_user['workspace']:
        return jsonify({
            'status': 'error',
            'message': 'Forbidden for users without full privileges'
        }), 403

    users.delete_one({'email': user_email})
    return jsonify({
        'status': 'success',
        'message': "User removed successfully"
    }), 200


if __name__ == "__main__":
    app.run(debug=True)
