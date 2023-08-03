import datetime

from flask import request
from flask_jwt_extended import (create_access_token, get_current_user,
                                jwt_required)
from flask_restful import Resource, fields, marshal_with
from werkzeug.security import generate_password_hash

from custom_error import DataError, LogicError
from model import Staff, Subject_Tag, User, db


class Login_api(Resource):
    '''Api code for Login Manager'''

    output = {"user_id": fields.Integer, "username": fields.String,
              "email": fields.String, "role": fields.String,
              "approved": fields.Boolean(attribute='status')}

    @jwt_required()
    @marshal_with(output)
    def get(self):
        '''Returns the User details for the current user'''

        obj = get_current_user()  # get the current user object
        # Checking whether user record is present
        if obj is None:
            raise DataError(status_code=404)

        # Checking for role=staff then check for approval status
        if obj.role == 'staff':
            obj = Staff.query.filter_by(user_id=obj.user_id).first()

        return obj, 200

    @jwt_required
    @marshal_with(output)
    def put(self):
        '''Modifies the User details for the current user'''

        obj = get_current_user()
        form = request.get_json()

        # Checking whether user record is present
        if obj is None:
            raise DataError(status_code=404)

        # Input data checking
        if form.get('password') is None and form.get('role') is None:
            raise DataError(status_code=400)
        if form.get('password') is not None:
            if type(form.get('password')) != str or len(form.get('password')) <= 4:
                raise LogicError(status_code=400, error_code="USER002",
                                 error_msg="Password must be string with length>4.")
            else:
                obj.password = form.get("password")
        if form.get('role') is not None:
            if type(form.get('role')) != str or len(form.get('role')) == 0:
                raise LogicError(status_code=400, error_code="USER004",
                                 error_msg="Role must be a non empty string.")
            else:
                obj.role = form.get("role", None)

        db.session.commit()
        return obj, 202

    @jwt_required()
    def delete(self):
        '''Deletes the current user details'''

        obj = get_current_user()

        if obj.role == 'staff':
            obj = Staff.query.filter_by(user_id=obj.user_id).first()
        # Checking whether user record is present
        if not obj:
            raise DataError(status_code=404)

        db.session.delete(obj)
        db.session.commit()
        return '', 200

    def post(self):
        '''Creates a new User details'''

        form = request.get_json()

        # Checking whether a user record with same username is present
        if User.query.filter_by(username=form.get('username')).first():
            raise DataError(status_code=409)

        # If role=staff then insert tag-id into Staff table
        if form.get('role') == 'staff':
            # Checking if tag-id is correct or not
            if Subject_Tag.query.filter_by(subject_id=form.get('subject_id')).first() is None:
                raise DataError(status_code=404)

            obj = Staff(username=form.get('username'), email=form.get("email"),
                        password=generate_password_hash(form.get("password")), role=form.get("role"),
                        subject_id=form.get('subject_id'))
        else:
            obj = User(username=form.get('username'), email=form.get("email"),
                       password=generate_password_hash(form.get("password")), role=form.get("role"))

        # Input data checking
        if obj.email is None or type(obj.email) != str or len(obj.email) == 0:
            raise LogicError(status_code=400, error_code="USER001",
                             error_msg="Email is required and must be a non empty string.")
        if obj.password is None or type(obj.password) != str or len(obj.password) <= 4:
            raise LogicError(status_code=400, error_code="USER002",
                             error_msg="Password is required and must be string with length>4.")
        if obj.username is None or type(obj.username) != str or len(obj.username) == 0:
            raise LogicError(status_code=400, error_code="USER003",
                             error_msg="Username is required and must be a non empty string.")
        if form.get("role") is None or type(form.get("role")) != str:
            raise LogicError(status_code=400, error_code="USER004",
                             error_msg="Role is required and must be a non empty string.")

        db.session.add(obj)
        db.session.commit()
        expire_time = datetime.timedelta(days=5)
        access_token = create_access_token(identity=form.get('username'),
                                           expires_delta=expire_time)

        if obj.role == 'staff':  # Checking for role=staff then return subject_id in response
            return {'access_token': access_token, "role": obj.role, "user_id": obj.user_id, "subject_id": obj.subject_id}, 200
        return {'access_token': access_token, "role": obj.role, "user_id": obj.user_id}, 200
