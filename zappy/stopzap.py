from	collections import defaultdict
from	datetime import datetime
from	django.utils.encoding import smart_str, smart_unicode
from	time import strftime, localtime
from	zapv2 import ZAPv2
import	argparse
import 	json
import	os
import	subprocess
import	sys
import datetime
import	time

#---- global constants ----
APIKEY = "demo"
date_stamp = datetime.datetime.now().strftime("%Y-%m-%d")
local_proxy = "http://localhost:8090"
session_id = "session-"+date_stamp
upstream_host = "http://www-proxy.us.oracle.com"
upstream_port = 80
zap = ""
report_dir = "/scratch/zap"
work_dir = "/tmp/zaproxy"
zap_dir = "/opt/zaproxy"
zap_host = "0.0.0.0"
zap_port = "8090"

def CountAlerts():  
  cnt = 0
  for alert in zap.core.alerts():
    cnt = cnt+1
  print("==\t\tAlert count: "+str(cnt))

def	PrintAlertSummary(e):
	print("==\tWriting the alert summary report")
	e.write("==\tAlerts Summary Report:")
	# create a data structure to match our output
	d = defaultdict(list)
	for alert in zap.core.alerts():
		name = alert.get("risk")+" Alert:\t"+alert.get("name")+"\n\nDescription:\n"+alert.get("description")+"\n\nsolution:\n"+alert.get("solution")+"\n\nreference:\n"+alert.get("reference")
		d[name].append([alert.get("url"),alert.get("messageId")])
	for k,v in d.items():
		e.write("\n"+k+"\n")
		for urlinfo in v:
			url=urlinfo[0]
			msgid=urlinfo[1]
			e.write("\t"+msgid+"\t"+url+"\n")

def	PrintAlertDetails(e):
	print("==\tWriting the Alert Details Report")
	e.write("==\tAlerts Detailed Report:")
	# create a data structure to match our output
	d = defaultdict(list)
	for alert in zap.core.alerts():
		name = alert.get("risk")+" Alert:\t"+alert.get("name")+"\n\nDescription:\n"+alert.get("description")+"\n\nsolution:\n"+alert.get("solution")+"\n\nreference:\n"+alert.get("reference")
		d[name].append([alert.get("url"),alert.get("messageId")])
	for k,v in d.items():
		e.write("\n"+k+"\n")
		for urlinfo in v:
			id=urlinfo[1]
			e.write("\n\n======== message "+str(id)+" ========\n")
			msg=zap.core.message(id)
			reqhdr=msg['requestHeader'].split("\r\n")
			for line in reqhdr:
				e.write(line+"\n")
			reqbody=msg['requestBody']
			e.write(smart_str(reqbody))
			e.write("\n\n------------------ response -----------------\n")
			resphdr=msg['responseHeader'].split("\r\n")
			for line in resphdr:
				e.write(line+"\n")
			respbody=msg['responseBody']
			for line in respbody:
				for l in line:
					e.write(smart_str(l))

def	PrintMessages(e):
	print("(*)\t\tPrintMessages")
	e.write("\t\t ZAP Messages\n\n")
	for msg in zap.core.messages():
			e.write("\n\n============ message #"+msg.get('id')+" ============\n")
			reqhdr=msg['requestHeader'].split("\r\n")
			for line in reqhdr:
				e.write(line+"\n")
			reqbody=msg['requestBody']
			e.write(smart_str(reqbody))
			e.write("\n\n------------------ response -----------------\n")
			resphdr=msg['responseHeader'].split("\r\n")
			for line in resphdr:
				e.write(line+"\n")
			respbody=msg['responseBody']
			for line in respbody:
				for l in line:
					e.write(smart_str(l))

def	GenerateReports():
	# Generate reports
	CountAlerts()
	print("==\tGenerating reports")
	rptfile=report_dir+"/zap-report.html"
	with open(rptfile,'w') as f:
		f.write(zap.core.htmlreport())
	rptfile=report_dir+"/alert-summary.txt"
	with open(rptfile,'w') as f:
		PrintAlertSummary(f)
	rptfile=report_dir+"/alert-details.txt"
	with open(rptfile,'w') as f:
		PrintAlertDetails(f)
	rptfile=report_dir+"/urls.txt"
	with open(rptfile,'w') as f:
		for url in zap.core.urls:
			f.write(url+"\n")
	rptfile=report_dir+"/all-messages.txt"
	with open(rptfile,'w') as f:
		PrintMessages(f)


def	PrintTotals():
	global zap
	print("\n------------------------------------------------------------------")
	print("==\tTotal URLS Processed:\t"+str(len(zap.core.urls)))
	print("==\tTotal number of alerts:\t"+zap.core.number_of_alerts())
	print("==\tTotal messages processed:\t"+zap.core.number_of_messages())
	print("\n------------------------------------------------------------------")
def	StopZap():
	global zap
	zap = ZAPv2(apikey=APIKEY,proxies={'http': local_proxy, 'https': local_proxy})
	GenerateReports()
	PrintTotals()
	zap.core.save_session(name=session_id,apikey="demo")
	zap.core.shutdown(APIKEY)


if __name__ == "__main__":
	StopZap()
