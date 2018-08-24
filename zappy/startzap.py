import logging
import subprocess
import time
import datetime
from zapv2 import ZAPv2

class   StartZap(object):
    """
    Start zaproxy on a provided port.

    The default port is 8080.
    """

    def __init__(self, port="8080"):
        self.APIKEY = "demo"
        self.date_stamp = datetime.datetime.now().strftime("%Y-%m-%d")
        self.local_proxy = "http://localhost:8090"
        self.session_id = "demo"+date_stamp
        self.upstream_host = "http://www-proxy.us.oracle.com"
        self.upstream_port = 80
        self.zap = ""
        self.work_dir = "/tmp/zaproxy"
        self.zap_dir = "/opt/zaproxy"
        self.zap_host = "0.0.0.0"
        self.zap_port = port

    def	StartZap():
	    zapcmd = self.zap_dir+"/zap.sh"
	    subprocess.Popen([zapcmd,
		    "-daemon",
		    "newsession", self.session_id,
		    "-installdir", self.zap_dir,
		    "-dir", self.work_dir,
		    "-host", self.zap_host,
		    "-port", self.zap_port,
		    "-config", "api.key="+self.APIKEY,
		    "-config", "api.addrs.addr.name=.*",
		    "-config", "api.addrs.addr.regex=true",
		    "-config", "ajaxSpider.browserId=htmlunit",
		    "-config", "scanner.attackOnStart=true -",
		    "-config", "connection.dnsTtlSuccessfulQueries=-1"]
		    )
	    time.sleep(60)
	    zap = ZAPv2(apikey=APIKEY,proxies={'http': local_proxy, 'https': local_proxy})

	zap.core.set_option_proxy_chain_name(upstream_host)
	zap.core.set_option_proxy_chain_port(upstream_port)
	zap.core.set_option_timeout_in_secs(60,apikey=APIKEY)
	zap.pscan.enable_all_scanners()
	print("ZAProxy is ready for use.")


if __name__ == "__main__":
	StartZap()
