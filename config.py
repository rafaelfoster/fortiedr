
import configparser as cp

class Config():

    config_file = "config/config.ini"

    def __init__(self) -> None:
        pass

    def get(self, param, section = "default"):

        config_file = cp.ConfigParser(allow_no_value=True)
        config_file.read(self.config_file)

        value = config_file.get(section, param)
        if any(value.lower() == f for f in ['no', 'n']): return False
        if any(value.lower() == f for f in ['yes', 'y']): return True
        
        return value
