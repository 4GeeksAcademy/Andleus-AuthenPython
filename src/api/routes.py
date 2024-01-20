"""
This module takes care of starting the API Server, Loading the DB and Adding the endpoints
"""
from flask import Flask, request, jsonify, url_for, Blueprint
from api.models import db, User
from api.utils import generate_sitemap, APIException
from flask_cors import CORS
from flask_jwt_extended import create_access_token , jwt_required , get_jwt_identity , get_jwt

api = Blueprint('api', __name__)

# Allow CORS requests to this API
CORS(api)


@api.route('/hello', methods=['POST', 'GET'])
def handle_hello():

    response_body = {
        "message": "Hello! I'm a message that came from the backend, check the network tab on the google inspector and you will see the GET request"
    }

    return jsonify(response_body), 200

@api.route('/login', methods=['POST'])
def login_user():
    email = request.json.get("email", None)
    password = request.json.get("password", None)
    # user = User.query.filter_by(email=email).first()
    user = User.query.filter_by(email=email, password=password).first()
    # if user is None:
    if user is None:
        return jsonify({"message":"User not found"}), 404
    # token = create_access_token(identity = user.id , additional_claims = {"role":"admin"})
    token = create_access_token(identity = user.id , additional_claims = {"role":"user"})
    return jsonify({"message":"Login Successful","token":token}) , 200



@api.route('signup', methods=['POST'])
def signup():
    data = request.get_json()
    if 'email' not in data or 'password' not in data:
        return jsonify({"error": "Where are my requirements?"})
    
    
    new_user = User(email=data['email'], password=data['password'], is_active=True)
    
    db.session.add(new_user)
    db.session.commit()

    return jsonify({"message": "User added successfully"}), 201


@api.route('/allUsers')
@jwt_required()
def allUsers():
    user_id = get_jwt_identity()
    # claims = ()
    # user = User.query.get(user_id)
    users = User.query.with_entities(User.id, User.email).all()
    response = [
            {
                "id": user.id,
                "email": user.email
            }
            for user in users
        ]
    return jsonify(response), 200



@api.route('/private')
@jwt_required()
def private():
    user_id = get_jwt_identity()
    # claims = ()
    # user = User.query.get(user_id)
    response = {
        "user_id" : user_id,
        # "user_pass": user.password
        # "claims" : claims,
        # "isActive" : user.is_active
    }
    return jsonify(response), 200
