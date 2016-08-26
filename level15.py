#Gets a list of cisco web servers and checks to see if level 15 access is available in the browser
#Looking for page similar to this: http://ptgmedia.pearsoncmg.com/images/chap15_1587051109/elementLinks/15fig02.gif
#Any additional changes can be made in getCiscoServer
import requests
import json
import urllib3

#add the SecurityCenter login information:
login = ''
password = ''
url = 'https://'

requests.packages.urllib3.disable_warnings()

def getTokenCookie():
	headers = {'Content-type': 'application/json'} #default header for getting token
	sc = requests.request('post', url+'/rest/token',
				data=json.dumps({'username':login, 'password':password}),
				headers=headers,
				verify=False)
	cookie = sc.cookies
	token = sc.json()['response']['token']
	login_header = {'X-SecurityCenter':str(token)}
	headers.update(login_header)
<<<<<<< HEAD
=======
 
>>>>>>> origin/master
	return(cookie,headers)


#gets a list of all open ports for any cisco web server.
#returns them to for testing ips.
def getOpenPorts(headers,cookie):
	
	portList = []

	listPorts = requests.request('post',url+'/rest/analysis',
			data=json.dumps({"query":{"name":"","description":"","context":"","status":-1,"createdTime":0,"modifiedTime":0,"groups":[],"type":"vuln","tool":"sumport","sourceType":"cumulative","startOffset":0,"endOffset":50,"filters":[{"id":"pluginText","filterName":"pluginText","operator":"=","type":"vuln","isPredefined":"true","value":"cisco-IOS"},{"id":"pluginID","filterName":"pluginID","operator":"=","type":"vuln","isPredefined":"true","value":"10107"}],"sortColumn":"severity","sortDirection":"desc","vulnTool":"sumport"},"sourceType":"cumulative","sortField":"severity","sortDir":"desc","columns":[],"type":"vuln"}),
			headers=headers,
			verify=False,
			cookies=cookie)

	ciscoPorts = listPorts.json()["response"]["results"]
	
	print("Open ports on Cisco web servers:")
	for p in ciscoPorts:
		print(p['port'])
		#adds each port to the list
		portList.append(p['port'])
	#returns the list
	return portList

#need to get a list of ports that are open for cisco servers
def getCiscoServer(headers,cookie,ports):
	counter = 0

	listCiscoHosts = requests.request('post',url+'/rest/analysis',
				data=json.dumps({"query":{"name":"","description":"","context":"","status":-1,"createdTime":0,"modifiedTime":0,"groups":[],"type":"vuln","tool":"sumip","sourceType":"cumulative","startOffset":0,"endOffset":50,"filters":[{"id":"pluginID","filterName":"pluginID","operator":"=","type":"vuln","isPredefined":"true","value":"10107"},{"id":"pluginText","filterName":"pluginText","operator":"=","type":"vuln","isPredefined":"true","value":"cisco"}],"sortColumn":"score","sortDirection":"desc","vulnTool":"sumip"},"sourceType":"cumulative","sortField":"score","sortDir":"desc","columns":[],"type":"vuln"}),
				headers=headers,
				verify=False,
				cookies=cookie)

	hosts = listCiscoHosts.json()["response"]["results"]
	
#	right now each host is checked against each port just in case. This can be modified later on
# 	outer loop gets each cisco ip with a web server. inside loop tests the host against every open cisco port

	for h in hosts:
#		used for troubleshooting. Uncomment to show all cisco devices in SecurityCenter
#		print(h['ip'])
		for p in ports:
			try:
				webServer = requests.get("http://"+h['ip']+":"+p)
				webPage = str(webServer.content)
#				modify here to make changes in what to search for on the page
				if("13,14,15" in webPage):
					print(h['ip'] + ":" + p + " appears to be level 15 access without auth")
					counter += 1					
			
			except requests.exceptions.RequestException as e:  
   				 print("Connection Refused: " + h['ip'] + " on port " + p)
		
	if(counter == 0):
		print("\n\nNo Cisco devices with level 15 web access found\n")
	else:
		print("\n\nFound " + counter + " devices with level 15 acces\n")

if __name__ == '__main__':
	print("Getting logged into SecurityCenter...")	
	#gets the login information
	cookie,headers = getTokenCookie()
<<<<<<< HEAD
	ports = getOpenPorts(headers,cookie)
	getCiscoServer(headers,cookie,ports)
=======
	getCiscoServer(headers,cookie)
>>>>>>> origin/master
