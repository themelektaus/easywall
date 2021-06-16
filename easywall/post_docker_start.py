from easywall.__main__ import CONFIG_PATH
from easywall.config import Config
from easywall.easywall import Easywall
config = Config(CONFIG_PATH)
easywall = Easywall(config)
easywall.postprocess_iptables()