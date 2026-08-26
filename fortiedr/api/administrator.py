from pydantic import BaseModel, Field
from typing import Union, List

class IntOrListOfInt(BaseModel):
    value: Union[int, List[int]]

class Administrator:
    def __init__(self, conn):
        self.conn = conn

    def list_system_summary(self, organization: str = None):
        params = {
            'organization': organization
        }
        return self.conn.get("/management-rest/admin/list-system-summary", params=params)

    def upload_license(self, licenseBlob: bytes):
        return self.conn.upload("/management-rest/admin/upload-license", file={'licenseBlob': licenseBlob})

    def list_users(self, organization: str = None):
        params = {
            'organization': organization
        }
        return self.conn.get("/management-rest/admin/users", params=params)

    def get_user(self, username: str, organization: str = None):
        params = {
            'organization': organization
        }
        return self.conn.get(f"/management-rest/admin/users/{username}", params=params)

    def delete_user(self, username: str, organization: str = None):
        params = {
            'organization': organization
        }
        return self.conn.delete(f"/management-rest/admin/users/{username}", params=params)

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
        return self.conn.send("/management-rest/admin/users", params=params)

    def update_user(self, username: str, firstName: str = None, lastName: str = None, password: str = None, confirmPassword: str = None, email: str = None, title: str = None, role: str = None, restApi: bool = None, customScript: bool = None, remoteShell: bool = None, organization: str = None):
        params = {
            'firstName': firstName,
            'lastName': lastName,
            'password': password,
            'confirmPassword': confirmPassword,
            'email': email,
            'title': title,
            'role': role,
            'restApi': restApi,
            'customScript': customScript,
            'remoteShell': remoteShell,
            'organization': organization
        }
        return self.conn.update(f"/management-rest/admin/users/{username}", params=params)
