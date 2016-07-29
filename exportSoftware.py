#################################################################################
# Name: exportSoftware.py
# 
# Description: Exporting the software installed contains additional information. 
# This script uses the following plugins to populate a csv file with a list of
# installed software/packages:
#
# 22869 - Software Enumeration(SSH)
# 20811 - Microsoft Windows Installed Software Enumeration
#
# Usage: Run the script and the Windows csv will be generated followed by the
# Unix csv. By default all reports are generated in the directory the script
# is located
#
# Note: The script will only report on hosts that the user has access to.
#
# Script was written with Python3 and will need requests and urllib3 installed
# using pip
#
################################################################################

import requests
import json
import urllib3
import csv
import os

login = '' #change to the SecurityCenter username
password = '' #change to the SecurityCenter password
url = 'https://' #change to the Securitycenter IP. Be sure to leave the https://

headers = {'Content-Type':'application/json'}
requests.packages.urllib3.disable_warnings()

def getTokenCookie():
	sc = requests.request('post',url+'/rest/token',
		data=json.dumps({'username':login, 'password':password}),
		headers=headers,
		verify=False)

	cookie = sc.cookies
	token = sc.json()['response']['token']
	login_header = {'X-SecurityCenter':str(token)}
	headers.update(login_header)

	return(cookie,headers)

#gets a count of all the windows hosts. if you have more than 5000 hosts change the endOffset below
#eventually will also take the Linux plugin ID
def getHostCount(pluginID):
	counter = 0
	hostCount = requests.request('post',url+'/rest/analysis',
		data=json.dumps({"query":{"name":"","description":"","context":"","status":-1,"createdTime":0,"modifiedTime":0,"groups":[],"type":"vuln","tool":"sumip","sourceType":"cumulative","startOffset":0,"endOffset":5000,"filters":[{"id":"pluginID","filterName":"pluginID","operator":"=","type":"vuln","isPredefined":"true","value":pluginID},{"id":"pluginName","filterName":"pluginName","operator":"=","type":"vuln","isPredefined":"true","value":"installed"}],"sortColumn":"score","sortDirection":"desc","vulnTool":"sumip"},"sourceType":"cumulative","sortField":"score","sortDir":"desc","columns":[],"type":"vuln"}),
		headers=headers,
		verify=False,
		cookies=cookie)
	
	hosts = hostCount.json()['response']['results']
	
	
	for h in hosts:
		if 'ip' in h:
			counter = counter + 1
	
	return(counter)	

#gets a count of all the linux hosts. 
#will be going away in favor of getHostCount()

def linuxCounter():
	counter = 0
	hostCount = requests.request('post',url+'/rest/analysis',
		data=json.dumps({"query":{"name":"","description":"","context":"","status":-1,"createdTime":0,"modifiedTime":0,"groups":[],"type":"vuln","tool":"sumip","sourceType":"cumulative","startOffset":0,"endOffset":5000,"filters":[{"id":"pluginID","filterName":"pluginID","operator":"=","type":"vuln","isPredefined":"true","value":"22869"}],"sortColumn":"score","sortDirection":"desc","vulnTool":"sumip"},"sourceType":"cumulative","sortField":"score","sortDir":"desc","columns":[],"type":"vuln"}),
		headers=headers,
		verify=False,
		cookies=cookie)
	
	hosts = hostCount.json()['response']['results']

	for h in hosts:
		if 'ip' in h:
			counter = counter + 1
	
	return(counter)

def windowsInstalled(cookie,headers):
	counter = getHostCount(20811) #pass the windows plugin to get the total amount of hosts
	count = 1

	softwareInstalled = requests.request('post',url+'/rest/analysis',
		data=json.dumps({"query":{"name":"","description":"","context":"","status":-1,"createdTime":0,"modifiedTime":0,"groups":[],"type":"vuln","tool":"vulndetails","sourceType":"cumulative","startOffset":0,"endOffset":counter,"filters":[{"id":"pluginID","filterName":"pluginID","operator":"=","type":"vuln","isPredefined":"true","value":"20811"},{"id":"pluginName","filterName":"pluginName","operator":"=","type":"vuln","isPredefined":"true","value":"installed"}],"vulnTool":"vulndetails"},"sourceType":"cumulative","columns":[],"type":"vuln"}),
		headers=headers,
		verify=False,
		cookies=cookie)
	
	installed = (softwareInstalled.json()['response']['results'])
	
	#file to write
	with open('windows_inventory.csv', 'w', newline='') as fp:
		a = csv.writer(fp,lineterminator='')
		#loops through to gather dns, ip, netbios and plugin text
		for item in installed:
			dns = item['dnsName']
			ip = item['ip']
			netbios = item['netbiosName']
			text = item['pluginText']
			text = removeTags(text) #need to remove the plugin_output tags before writing
			#The following line can be uncommented for troubleshooting
			#print(text)			
			label = ("\nHOST:   " + dns + "   IP:    " + ip + "   NETBIOS:    " +  netbios + "   \n\n")
			print("Writing " , count , " of " , counter)
			a.writerows(label+text)
			count = count + 1
			if(counter > 200):
				os.system("clear")


def unixInstalled(cookie,headers):
	print("Getting a count of all the Linux/Unix hosts")
	counter = linuxCounter()
	count = 1

	softwareInstalled = requests.request('post',url+'/rest/analysis',
		data=json.dumps({"query":{"name":"","description":"","context":"","status":-1,"createdTime":0,"modifiedTime":0,"groups":[],"type":"vuln","tool":"vulndetails","sourceType":"cumulative","startOffset":0,"endOffset":counter,"filters":[{"id":"pluginID","filterName":"pluginID","operator":"=","type":"vuln","isPredefined":"true","value":"22869"},{"id":"pluginName","filterName":"pluginName","operator":"=","type":"vuln","isPredefined":"true","value":"enumeration"}],"vulnTool":"vulndetails"},"sourceType":"cumulative","columns":[],"type":"vuln"}),
		headers=headers,
		verify=False,
		cookies=cookie)
	
	installed = (softwareInstalled.json()['response']['results'])
	#file to write
	with open('unix_inventory.csv', 'w', newline='') as fp:
		a = csv.writer(fp,lineterminator='')
		for item in installed:
			ip = item['ip']
			text = item['pluginText']
			text = removeTags(text)
			print("Writing ", count, " of ", counter)
			a.writerows(ip+text)		
			count = count + 1 #updates the counter
			#keeps the screen clear for more than 200 hosts when updating the count
			if(counter > 200):
				os.system("clear")
		
#Strips the plugin_output tegs from the pluginText field
def removeTags(text):
	import re
	result = re.sub("<.*?>","",text)
	return result


if __name__ == '__main__':
	print("Getting logged into SecurityCenter...")
	cookie,headers = getTokenCookie()
	
	windowsInstalled(cookie,headers)
	print("Wrote the Windows software installed file.")
	
	unixInstalled(cookie,headers)
	print("Wrote the Linux/Unix software installed file.")
	#logs out
	requests.request('delete',url+'/rest/token',
		headers=headers,
		verify=False,
		cookies=cookie)
