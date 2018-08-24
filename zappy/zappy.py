"""
zappy.ZAPpy
@author Donald Raikes
@date 06/12/2018

This package includes some functions that make it easier to use
the zaproxy python apis.

Constructs included:
1. Start and stop zap.
2. Get a status of zap alerts and messages processed during the current session.
3. Create/save sessions.
4. Generate some custom text reports.
"""


import  logging
import  os
import  sys
import  subprocess
import  time
import  datetime
import threading

from zapv2 import ZAPv2


class   ZAPPY(object):
    """Encapsulate the abstraction in this class."""
    localProxy=""
    zapHost="localhost"
    zapPort="8080"
    zapHome="/opt/zaproxy"
    zapDir="/tmp/zaproxy"
    upstreamHost=""
    upstreamPort=""
    apiKey=""
    zap=""

    def __init__(self, apiKey, sessionId,*args,**kwargs):
        """Setup the class attributes."""
        logging.basicConfig(level=logging.INFO)
        self.apiKey = apiKey
        self.sessionId = sessionId
        self.zapHome = kwargs.get('zapHome', self.zapHome)
        self.zapDir = kwargs.get('zapDir', self.zapDir)
        self.zapPort = kwargs.get('zapPort', self.zapPort)
        self.upstreamHost = kwargs.get('upstreamHost', self.upstreamHost)
        self.upstreamPort = kwargs.get('upstreamPort', self.upstreamPort)
        self.localProxy=self.zapHost+":"+self.zapPort

    def StartZap(self):

        logging.info("Starting the zaproxy server...")
        zapcmd = self.zapHome+"/zap.sh"
        try:
            subprocess.Popen([zapcmd,
                "-daemon",
                "newsession", self.sessionId,
                "-installdir", self.zapHome,
                "-dir", self.zapDir,
                "-host", self.zapHost,
                "-port", self.zapPort,
                "-config", "api.key="+self.apiKey,
                "-config", "api.addrs.addr.name=.*",
                "-config", "api.addrs.addr.regex=true",
                "-config", "ajaxSpider.browserId=htmlunit",
                "-config", "scanner.attackOnStart=true -",
                "-config", "connection.dnsTtlSuccessfulQueries=-1"]
                )
        except:
            sys.exit(-1)

        time.sleep(60)
        zap = ZAPv2(apikey=self.apiKey,proxies={'http': self.localProxy, 'https': self.localProxy})

        if self.upstreamHost != "":
            zap.core.set_option_proxy_chain_name(self.upstreamHost)
            zap.core.set_option_proxy_chain_port(self.upstreamPort)
        zap.core.set_option_timeout_in_secs(60,apikey=self.apiKey)
        zap.pscan.enable_all_scanners()
        self.zap=zap
        logging.info("Zaproxy is ready for use.")

    def StopZap(self):
        """ Stop the zap process."""
        try:
            self.zap.core.save_session(name=self.sessionId,apikey=self.apiKey)
            self.zap.core.shutdown(self.apiKey)
            logging.info("Zap has been successfully shutdown.")
        except:
            logging.info("Error shutting down ZAP")
            system.exit(-1)
if __name__ == "__main__":
    zaproxy=ZAPPY("testkey","testsession",zapPort="8090")
    zaproxy.StartZap()
    zaproxy.StopZap()
