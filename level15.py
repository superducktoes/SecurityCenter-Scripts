​

#Gets a list of cisco web servers and checks to see if level 15 access is available in the browser

import requests
import json
import urllib3

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

	return(cookie,headers)


#need to get a list of ports that are open for cisco servers

def getCiscoServer(headers,cookie):

	listCiscoHosts = requests.request('post',url+'/rest/analysis',
			data=json.dumps({"query":{"name":"","description":"","context":"","status":-1,"createdTime":0,"modifiedTime":0,"groups":[],"type":"vuln","tool":"sumip","sourceType":"cumulative","startOffset":0,"endOffset":50,"filters":[{"id":"pluginID","filterName":"pluginID","operator":"=","type":"vuln","isPredefined":"true","value":"10107"},{"id":"pluginText","filterName":"pluginText","operator":"=","type":"vuln","isPredefined":"true","value":"cisco-IOS"}],"sortColumn":"score","sortDirection":"desc","vulnTool":"sumip"},"sourceType":"cumulative","sortField":"score","sortDir":"desc","columns":[],"type":"vuln"}),
			headers=headers,
			verify=False,
			cookies=cookie)

			hosts = listCiscoHosts.json()["response"]["results"]
			#prints a list of cisco devices with web server	

			for h in hosts:
				print(h['ip'])

if __name__ == '__main__':
	print("Getting logged into SecurityCenter...")	
	#gets the login information
	cookie,headers = getTokenCookie()
	getCiscoServer(headers,cookie)