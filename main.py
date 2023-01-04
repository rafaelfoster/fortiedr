from lib.connector import Auth
from lib.fortiedr_collectors import Collectors
from config import Config

def main():

    collectors = Collectors()

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

if __name__ == "__main__":
    main()