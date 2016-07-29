########################################################################
# Name: createAssetFromFile.py
#
# Description: This script was designed for importing lists of hosts
# from other tools into SecurityCenter as static asset lists. The
# script can be re-run when files are added/updated to update the
# asset lists in Securitycenter.
#
# Usage: By default the script looks in ./assets for the files to import
# this directory will either need to be created or the script modified.
# Once the files are in the directory, the script will create one asset 
# per file using the filename and the contents of the file.
# Files can have IP's or CIDR on each line.
# 
# It is recommended to create a separate user for the script to use.
# This script will delete ALL assets that a user has created and 
# replace them with the files in the directory. 
# 
# Note: This script WILL DELETE all assets for the account provided
# and CANNOT be recovered.
# 
# Places where changes can be made to fit your environment are noted
# in the comments 
#
# Script was written for Python3 and will need requests and urllib3 
# installed using pip
######################################################################

import requests
import json
import os
import urllib3

login = '' #change to SecurityCenter username
password = '' #change to SecurityeCenter password
url = 'https://' #change to SecurityCenter IP. Make sure to keep https:// before IP

requests.packages.urllib3.disable_warnings()

#gets all of the login information that we'll need later

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


#creates an asset based on the file opened
def createAsset(cookie,headers,ips,assetName):
	str(ips)
	str(assetName)
	newasset = requests.request('post', url+'/rest/asset',
				data=json.dumps({"name":assetName,"status":-1,"createdTime":0,"tags":"","type":"static","definedIPs":ips}),
				headers=headers,
				verify=False,
				cookies=cookie)

	if(newasset.status_code != 200):
		print("Error adding asset ",assetName)


#deltes all assets for the user
def deleteAssets(cookie,headers):
	listassets = requests.request('get', url+'/rest/asset',
				headers=headers,
				verify=False,
				cookies=cookie)
	
	#gets a list of all the assets that a user has access to
	assetsToDelete = listassets.json()['response']['manageable']
	
	#goes through each id and deletes the asset
	for i in assetsToDelete:
		asset = i['id']
		deleteAssets = requests.request('delete',url+'/rest/asset/'+asset,
						headers=headers,
						verify=False,
						cookies=cookie)
		
	if(deleteAssets.status_code != 200):
		print("Error deleting asset ", i['name'])

if __name__ == '__main__':
	print("Getting logged into SecurityCenter...")
	
	#gets the login information
	cookie,headers = getTokenCookie()
	
	#delete all of the old assets first.	
	print("Removing old assets")
	deleteAssets(cookie,headers)

	#loop through and create assets using the filename
	print("Adding new/updated assets")
	for filename in os.listdir('./assets'):  #change the path if the files are stored in a different directory
		assetFile = open('./assets/'+filename,'r') #change this too if the above was modified
		ips = assetFile.read()
		createAsset(cookie,headers,ips,filename)
		assetFile.close()
	print("Done!")
	
	 #logs out
        requests.request('delete',url+'/rest/token',
                headers=headers,
                verify=False,
                cookies=cookie)
