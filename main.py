from flask import Flask, request, jsonify, Response
from pymongo import MongoClient, errors
from hashlib import sha256
import json
from bson import json_util, ObjectId
import jwt
from datetime import datetime,timedelta


app = Flask(__name__)
auth_user = "admin"
auth_password = "admin"
key = "bozshijack"


def getCollection():
    db = MongoClient("mongodb://1palette:Qy9jcErb3UKEnnJr@127.0.0.1:27017/")
    dbTest = db["test_authen_system"]
    collection = dbTest["users"]
    return collection


def is_pass_auth():
    if not(request.authorization and request.authorization.username == auth_user and request.authorization.password == auth_password):
        return False

    return True


def is_pass_auth_token(bearer):
    try:
        if not bearer:
            return "token missing"
        token = bearer.split()[1]
        user_id = jwt.decode(token, key, algorithms="HS256")
        collection = getCollection()
        query = {
            '_id': ObjectId(user_id['id'])
        }
        user = collection.find(user_id)
        if user is None:
            return "invalid token"
        return None
    except jwt.ExpiredSignatureError:
        print('token expired')
        return "token expired"
    except:
        return "token error"

@app.route('/register', methods=['POST'])
def register():
    response = Response()
    response.headers['Content-type'] = 'application/json; charset=utf-8'
    response.headers['Access-Control-Allow-Origin'] = '*'
    is_pass = is_pass_auth()
    if not is_pass:
        response.response = json.dumps({
            'status': 401,
            'message': "authentication failed"
        })
        response.status = "401"
        return response
    try:
        body = request.json
        username = None
        password = None
        if "username" in body:
            username = body["username"]
        if "password" in body:
            password = body["password"]
        if username is None or password is None:
            response.response = json.dumps({
                'status': 400,
                'message': "username or password missing."
            })
            response.status = "400"
            return response

        password = sha256(password.encode()).hexdigest()
        collection = getCollection()
        newUser = {
            'username': username,
            'password': password
        }
        collection.insert_one(newUser)
        userInserted = json.loads(JSONEncoder().encode(newUser))

        response.response = json.dumps({
            'status': 200,
            'data': userInserted
        })
        response.status = "200"

        return response
    except errors.DuplicateKeyError:
        response.response = json.dumps({
            'status': 400,
            'message': "Username already used."
        })
        response.status = "400"
        return response


@app.route('/login', methods=['POST'])
def login():
    response = Response()
    response.headers['Content-type'] = 'application/json; charset=utf-8'
    response.headers['Access-Control-Allow-Origin'] = '*'
    is_pass = is_pass_auth()
    if not is_pass:
        response.response = json.dumps({
            'status': 401,
            'message': "authentication failed"
        })
        response.status = "401"
        return response

    body = request.json
    username = None
    password = None
    if "username" in body:
        username = body["username"]
    if "password" in body:
        password = body["password"]

    if username == None or password == None:
        response.response = json.dumps({
            'status': 400,
            'message': "username or password missing."
        })
        response.status = "400"

        return response

    password = sha256(password.encode()).hexdigest()
    collection = getCollection()
    query = {
        "username": username,
        "password": password
    }
    user = collection.find_one(query)
    if user is None:
        response.response = json.dumps({
            'status': 401,
            'message': "username or password is wrong."
        })
        response.status = "401"
        return response

    data = json.loads(JSONEncoder().encode(user))
    expiredTime = datetime.now() + timedelta(minutes=10)
    print(expiredTime)
    token = jwt.encode({'id': data['_id'], 'exp' : expiredTime}, key, algorithm="HS256")

    response.response = json.dumps({
        'status': 200,
        'data': data,
        'token': token
    })
    response.status = "200"
    return response


@app.route('/test', methods=['GET'])
def get_data():

    response = Response()
    response.headers['Content-type'] = 'application/json; charset=utf-8'
    response.headers['Access-Control-Allow-Origin'] = '*'
    tokenError = is_pass_auth_token(request.headers.get('Authorization'))

    if tokenError:
        response.response = json.dumps({
            'status': 401,
            'message': tokenError
        })
        response.status = "401"
        return response
    response.response = json.dumps({
        'status': 200,
        'message': "Pass"
    })
    response.status = "200"
    return response

@app.route('/', methods=['GET'])
def check():

    response = Response()
    response.headers['Content-type'] = 'application/json; charset=utf-8'
    response.headers['Access-Control-Allow-Origin'] = '*'
    response.status = "200"
    return response

class JSONEncoder(json.JSONEncoder):
    def default(self, o):
        if isinstance(o, ObjectId):
            return str(o)
        return json.JSONEncoder.default(self, o)


if __name__ == '__main__':
    app.run(debug=True)
