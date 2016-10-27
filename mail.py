import requests
import json
import urllib3
import smtplib

login = ''
password = ''
url = ''

requests.packages.urllib3.disable_warnings()

def getTokenCookie():
    headers = {'Content-type': 'application/json'}
    sc = requests.post(url+'/rest/token',
                       data=json.dumps({'username':login,'password':password}),
                       headers=headers,
                       verify=False)
    cookie = sc.cookies
    token = sc.json()['response']['token']
    login_header = {'X-SecurityCenter':str(token)}
    headers.update(login_header)

    return(cookie,headers)

def sendMail():
    sender = 'test@tenablesc.com'
    receiver = {'nroy@tenable.com'}

    message = """From: SecurityCenter <test@sc.com>
    To: Test User <test@example.com>
    Subject: Scan Starting
    
    There is a scan starting in the next half hour
    """

    try:
        s = smtplib.SMTP('',25)
        s.sendmail(sender,receiver,message)
        print("sent email")
    except:
        print("There was an error sending the email")

if __name__=='__main__':
    print("Getting logged into SecurityCenter")

    cookie,headers = getTokenCookie()
    print("got cookies and header information")
    
    sendMail()
    
