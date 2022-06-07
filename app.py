import os
import re
import uuid
import flask
import pydantic

from typing import Union
# from pydantic import BaseModel
from flask import Flask, jsonify, request
from flask.views import MethodView
from flask_bcrypt import Bcrypt
from sqlalchemy import (
    Column,
    DateTime,
    ForeignKey,
    Integer,
    String,
    create_engine,
    func,
)
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import relationship, sessionmaker


app = flask.Flask('app')
# app.config.from_pyfile('settings.py')
bcrypt = Bcrypt(app)
PG_DSN = 'postgresql://admin_flask_advert:1234@127.0.0.1:5432/flask_advert'
# PG_DSN = 'postgresql://admin_flask_advert:1234@127.0.0.1:5432/flask_netology'
# # engine = create_engine(os.getenv("PG_DSN"))
engine = create_engine(PG_DSN)
Base = declarative_base()
Session = sessionmaker(bind=engine)


password_regex = re.compile(
    r"^(?=.*[a-z_])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*#?&_])[A-Za-z\d@$!#%*?&_]{8,200}$"
)
# password_regex = re.compile(
#     r"^(?=.*[a-z_]){8,200}$"
# )


class User(Base):
    __tablename__ = "user"
    id = Column(Integer, primary_key=True)
    user_name = Column(String(100), nullable=False, unique=True)
    email = Column(String(100), nullable=False, unique=True)
    password = Column(String(200), nullable=False)
    registration_time = Column(DateTime, server_default=func.now())
    adverts = relationship('Advert', backref='author')

    @classmethod
    def register(cls, session: Session, user_name: str, email: str, password: str):
        new_user = User(
            user_name=user_name,
            email=email,
            password=bcrypt.generate_password_hash(password.encode()).decode(),
        )
        session.add(new_user)
        try:
            session.commit()
            return new_user
        except IntegrityError:
            session.rollback()

    def check_password(self, password: str):
        return bcrypt.check_password_hash(self.password.encode(), password.encode())

    def to_dict(self):
        return {
            "user_name": self.user_name,
            "email": self.email,
            "id": self.id,
        }


class Advert(Base):
    __tablename__ = "advert"
    id = Column(Integer, primary_key=True)
    title = Column(String(100), nullable=False, unique=True)
    description = Column(String(200), nullable=False)
    created_at = Column(DateTime, server_default=func.now())
    # owner = Column(String(50), nullable=False)
    owner = Column(Integer, ForeignKey("user.id"))
    # user = relationship(User, lazy="joined")
    # user = relationship(User, backref="adverts")

    @classmethod
    def create(cls, session: Session, title: str, description: str, owner: int):
        author = (
            session.query(User)
            .filter(User.id == owner)
            .first()
        )
        # author = User(id=owner)

        new_advert = Advert(
            title=title,
            description=description,
            owner=author
        )
        session.add(new_advert)
        try:
            session.commit()
            return new_advert
        except IntegrityError:
            session.rollback()

    @classmethod
    def delete(cls, session: Session, advert_id: int):
        del_advert = (
            session.query(Advert)
            .filter(Advert.id == advert_id)
            .first()
        )
        session.delete(del_advert)
        try:
            session.commit()
        except IntegrityError:
            session.rollback()

    def to_dict(self):
        return {
            "title": self.title,
            "description": self.description,
            "id": self.id,
        }


class Token(Base):
    __tablename__ = "token"

    id = Column(UUID(as_uuid=True), default=uuid.uuid4, primary_key=True)
    creation_time = Column(DateTime, server_default=func.now())
    user_id = Column(Integer, ForeignKey("user.id"))
    user = relationship(User, lazy="joined")


Base.metadata.create_all(engine)


class HTTPError(Exception):
    def __init__(self, status_code: int, message: Union[str, list, dict]):
        self.status_code = status_code
        self.message = message


@app.errorhandler(HTTPError)
def handle_invalid_usage(error):
    response = jsonify({"message": error.message})
    response.status_code = error.status_code
    return response


def check_token(session):
    token = (
        session.query(Token)
        .join(User)
        .filter(
            User.user_name == request.headers.get("user_name"),
            Token.id == request.headers.get("token"),
        )
        .first()
    )
    if token is None:
        raise HTTPError(401, "invalid token")
    return token


class CreateUserModel(pydantic.BaseModel):
    user_name: str
    password: str
    email: str

    # @classmethod
    @pydantic.validator("password")
    def strong_password(cls, value: str):
        if not re.search(password_regex, value):
            raise ValueError("password to easy")

        return value


class CreateAdvertModel(pydantic.BaseModel):
    # еще не сделано
    title: str
    description: str

#     # @classmethod
#     @pydantic.validator("password")
#     def strong_password(cls, value: str):
#         if not re.search(password_regex, value):
#             raise ValueError("password to easy")
#
#         return value


def validate(unvalidated_data: dict, validation_model):
    try:
        return validation_model(**unvalidated_data).dict()
    except pydantic.ValidationError as er:
        raise HTTPError(400, er.errors())


class UserView(MethodView):
    def get(self, user_id: int):
        with Session() as session:
            token = check_token(session)
            if token.user.id != user_id:
                raise HTTPError(403, "auth error")
            return jsonify(token.user.to_dict())

    def post(self):
        with Session() as session:
            register_data = validate(request.json, CreateUserModel)
            return User.register(session, **register_data).to_dict()


class AdvertView(MethodView):
    # еще не сделано
    def get(self, advert_id: int):
        with Session() as session:
            return jsonify(Advert.to_dict())

    def post(self):
        with Session() as session:
            create_data = validate(request.json, CreateAdvertModel)
            return Advert.create(session, **create_data).to_dict()

    def delete(self):
        with Session() as session:
            # deleted_data = validate(request.json, CreateAdvertModel)
            return Advert.delete(session, **request.json).to_dict()


@app.route("/flask-app/api/login/", methods=["POST"])
def login():
    login_data = request.json
    with Session() as session:
        user = (
            session.query(User)
            .filter(User.user_name == login_data["user_name"])
            .first()
        )
        if user is None or not user.check_password(login_data["password"]):
            raise HTTPError(401, "incorrect user or password")
        token = Token(user_id=user.id)
        session.add(token)
        session.commit()
        return jsonify({"token": token.id})


# @app.route('/test', methods=['POST'])
# # @app.route('/flask-app/api/test')
# def test():
#     headers = request.headers
#     json_data = request.json
#     qs = request.args
#
#     return flask.jsonify({
#         'status': 'it works!',
#         'headers': dict(headers),
#         'json_data': dict(json_data),
#         'qs': dict(qs)
#     })
#     # return flask.jsonify({
#     #     'status': 'it works!'
#     #     })


app.add_url_rule(
    "/flask-app/api/user/<int:user_id>/", view_func=UserView.as_view("get_user"), methods=["GET"]
)
app.add_url_rule(
    "/flask-app/api/user/", view_func=UserView.as_view("register_user"), methods=["POST"]
)
# # еще не сделано
app.add_url_rule(
    "/flask-app/api/advert/<int:advert_id>/", view_func=AdvertView.as_view("get_advert"), methods=["GET"]
)
app.add_url_rule(
    "/flask-app/api/advert/", view_func=AdvertView.as_view("create_advert"), methods=["POST"]
)
app.add_url_rule(
    "/flask-app/api/advert/<int:advert_id>/", view_func=AdvertView.as_view("delete_advert"), methods=["DELETE"]
)


if __name__ == '__main__':
    app.run()