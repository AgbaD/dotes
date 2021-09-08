#!/usr/bin/python3
# Author:   @AgbaD || @agba_dr3

from jsonschema import validate
from jsonschema.exceptions import ValidationError, SchemaError

userRegSchema = {
    "type": "object",
    "properties": {
        "email": {
            "type": "string",
            "format": "email",
            "minLength": 7
        },
        "fullname": {
            "type": "string",
            "maxLength": 27,
            "minLength": 3
        },
        "password": {
            "type": "string",
            "minLength": 8
        },
        "workspace": {
            "type": "string"
        },
    },
    "required": ["fullname", "email", "password", "workspace"],
    "additionalProperties": False
}

userLoginSchema = {
    "type": "object",
    "properties": {
        "email": {
            "type": "string",
            "format": "email"
        },
        "password": {
            "type": "string"
        },
    },
    "required": ["email", "password"],
    "additionalProperties": False
}

userDbSchema = {
    "type": "object",
    "properties": {
        "email": {
            "type": "string",
            "format": "email",
            "minLength": 7
        },
        "fullname": {
            "type": "string",
            "maxLength": 27,
            "minLength": 3
        },
        "password": {
            "type": "string",
            "minLength": 8
        },
        "public_id": {
            "type": "string",
        },
        "workspace": {
            "type": "string"
        },
        "is_admin": {
            "type": 'boolean'
        }
    },
    "required": ["fullname", "email", "password", "public_id", "workspace"],
    "additionalProperties": False
}


def validate_login(user):
    try:
        validate(user, userLoginSchema)
        return {"msg": "success"}
    except SchemaError as e:
        return {"msg": "error", "error": e.message}
    except ValidationError as e:
        return {"msg": "error", "error": e.message}


def validate_user_db(data):
    try:
        validate(data, userDbSchema)
        return {"msg": "success"}
    except SchemaError as e:
        return {"msg": "error", "error": e.message}


def validate_reg(user):
    try:
        validate(user, userRegSchema)
        return {"msg": "success"}
    except SchemaError as e:
        return {"msg": "error", "error": e.message}
    except ValidationError as e:
        p = list(e.schema_path)
        print(p)
        print(len(p))
        if len(p) > 1:
            if p[1] == 'password' and p[2] == 'minLength':
                error_message = "Password too short, minimum length of 8"
                return {"msg": "error", "error": error_message}
            if p[1] == 'fullname':
                if p[2] == 'minLength':
                    error_message = "Fullname too short, minimum of 3 characters"
                    return {"msg": "error", "error": error_message}
                if p[2] == 'maxLength':
                    error_message = "Fullname too long, max of 27 characters"
                    return {"msg": "error", "error": error_message}
            if p[1] == 'email' and p[2] == 'minLength':
                error_message = "Email too short, minimum length of 7"
                return {"msg": "error", "error": error_message}
        return {"msg": "error", "error": e.message}
