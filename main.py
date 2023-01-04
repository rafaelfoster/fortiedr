from lib.connector import Auth
from lib.fortiedr_collectors import Collectors
from config import Config

def main():

    collectors = Collectors()

    collectors.list_unmanaged()

if __name__ == "__main__":
    main()