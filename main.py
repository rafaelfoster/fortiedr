import json
from config import Config
from lib.connector import Auth
from lib.fortiedr_users import Users
from lib.fortiedr_admin import Admin
from lib.fortiedr_collectors import Collectors

def main():

    collectors = Collectors()

    # An example of listing Unmanaged collectors

    status, data = collectors.list_unmanaged()
    if status:
        for collector in data:
            print("Name: \t\t{PARAM}".format(PARAM=collector['name']))
            print("Group: \t\t{PARAM}".format(PARAM=collector['collectorGroupName']))
            print("OS: \t\t{PARAM}".format(PARAM=collector['operatingSystem']))
            print("state: \t\t{PARAM}".format(PARAM=collector['state']))
            print("IP Address: \t{PARAM}".format(PARAM=collector['ipAddress']))
            print("Last Seen: \t{PARAM}".format(PARAM=collector['lastSeenTime']))
            print("\n")

    # An example of creating a group of collectors
    new_collector_group = {
        "name": "CollectorGroup_TEST", # Mandatory
        "organization" : "organization" 
    }

    status, data = collectors.create_group(new_collector_group)
    if status:
        print("Collector Group created!")
        print(data)

    # An example of listing collectors installers
    admin = Admin()

    status, data = admin.list_installers()
    if status:
        print(json.dumps(data, indent=4))
        for installer in data:
            print(installer)

    # Listing users
    users = Users()

    status, data = users.list()
    if status:
        print("Users created in FortiEDR Manager")
        print(json.dumps(data, indent=4))
    else:
        print("Error on request.")

if __name__ == "__main__":
    main()