from pydantic import BaseModel, Field
from typing import Union, List

class IntOrListOfInt(BaseModel):
    value: Union[int, List[int]]

class Users:
    def __init__(self, conn):
        self.conn = conn

    def create_user(self, firstName: str, lastName: str, password: str, confirmPassword: str, email: str, username: str, title: str, role: str, restApi: bool, customScript: bool, remoteShell: bool, organization: str = None):
        params = {
            'firstName': firstName,
            'lastName': lastName,
            'password': password,
            'confirmPassword': confirmPassword,
            'email': email,
            'username': username,
            'title': title,
            'role': role,
            'restApi': restApi,
            'customScript': customScript,
            'remoteShell': remoteShell,
            'organization': organization
        }
        return self.conn.send("/management-rest/users/create-user", params=params)

    def delete_user(self, username: str, organization: str = None):
        params = {
            'username': username,
            'organization': organization
        }
        return self.conn.delete("/management-rest/users/delete-user", params=params)

    def list_users(self, organization: str = None):
        params = {
            'organization': organization
        }
        return self.conn.get("/management-rest/users/list-users", params=params)

    def update_user(self, username: str, organization: str = None):
        params = {
            'username': username,
            'organization': organization
        }
        return self.conn.update("/management-rest/users/update-user", params=params)

    def get_user(self, username: str, organization: str = None):
        params = {
            'username': username,
            'organization': organization
        }
        return self.conn.get("/management-rest/users/get-user", params=params)
