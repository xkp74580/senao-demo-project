from flask import Flask
from flask_restful import Api, Resource, reqparse
from werkzeug.security import check_password_hash, generate_password_hash
import re

app = Flask(__name__)
api = Api(app)

users = []
test = []


class ErrorCodes:
    SUCCESS = {"success": True, "reason": ""}, 200
    USER_NOT_FOUND = {"success": False, "reason": "User not found"}, 404
    USER_EXISTS = {"success": False, "reason": "A user with same username already exists"}, 400
    AUTH_FAILED = {"success": False, "reason": "Authentication failed. Invalid password."}, 401
    OVER_MAX_RETRIES = {"success": False,
                        "reason": "Maximum number of failed attempts reached. Please contact System support."}, 401
    USER_DELETED = {"success": False, "reason": "User has been deleted"}, 200
    SUCCESSFUL_AUTH = {"success": False, "reason": "Successfully authenticated."}, 200

    USERNAME_FIELD_NOT_VALID = {"success": False,
                                "reason": "username field is required and its length must be between 3 to 32 characters."}, 400
    PASSWORD_FIELD_NOT_VALID = {"success": False,
                                "reason": "password field is required and its length must be between 3 to 32 characters and should both contains 1 uppercase letter, 1 lowercase letter and 1 number."}, 400


def valid_username(username):
    if 3 <= len(username) <= 32:
        return True
    else:
        return False


def valid_password(password):
    if 8 <= len(password) <= 32 and re.match(r'^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)[a-zA-Z\d]{3,32}$', password):
        return True
    else:
        return False


class UserResource(Resource):
    parser = reqparse.RequestParser(bundle_errors=True)
    parser.add_argument('username', type=str, required=True, location='json',
                        help="")
    parser.add_argument('password', type=str, required=True, location='json',
                        help="")

    # GET /users/
    # 查詢使用者
    def get(self, username):
        user = next((u for u in users if u['username'] == username), None)
        if user is None:
            return ErrorCodes.USER_NOT_FOUND

        user_copy = user.copy()
        existing_password = user_copy['password']
        if existing_password:
            user_copy.pop('password', None)

        return user_copy, 200

    # POST /users
    # 建立使用者
    def post(self):
        data = self.parser.parse_args()
        if any(u['username'] == data['username'] for u in users):
            return ErrorCodes.USER_EXISTS

        if not valid_username(data['username']):
            return ErrorCodes.USERNAME_FIELD_NOT_VALID

        if not valid_password(data['password']):
            return ErrorCodes.PASSWORD_FIELD_NOT_VALID

        user = {'id': len(users) + 1, 'username': data['username'],
                'password': generate_password_hash(data['password']), 'authFailedCount': 0}
        users.append(user)
        return ErrorCodes.SUCCESS

    # PUT /users/
    # 更新使用者資訊
    def put(self, username):
        data = self.parser.parse_args()
        user = next((u for u in users if u['username'] == username), None)
        if user is None:
            return ErrorCodes.USER_NOT_FOUND

        new_password = data['password']
        if new_password:
            if valid_password(new_password):
                data['password'] = generate_password_hash(new_password)
            else:
                return ErrorCodes.PASSWORD_FIELD_NOT_VALID

        data['authFailedCount'] = 0
        user.update(data)
        return ErrorCodes.SUCCESS

    # DELETE /users/
    # 刪除使用者
    def delete(self, username):
        global users
        users = [u for u in users if u['username'] != username]
        return ErrorCodes.SUCCESS


class AuthResource(Resource):
    parser = reqparse.RequestParser()
    parser.add_argument('username', type=str, required=True, help="Username is required.")
    parser.add_argument('password', type=str, required=True, help="Password is required.")

    def post(self):
        data = AuthResource.parser.parse_args()
        username = data.get('username')
        password = data.get('password')
        user = next((u for u in users if u['username'] == username), None)
        if user is None:
            return ErrorCodes.USER_NOT_FOUND

        print(user)
        if user['authFailedCount'] > 3:
            return ErrorCodes.OVER_MAX_RETRIES
        elif check_password_hash(user['password'], password):
            return ErrorCodes.SUCCESSFUL_AUTH
        else:
            user['authFailedCount'] += 1
            return ErrorCodes.AUTH_FAILED


api.add_resource(UserResource, '/users/<string:username>', '/users')
api.add_resource(AuthResource, '/auth')

if __name__ == '__main__':
    app.run(host='0.0.0.0', debug=True)
