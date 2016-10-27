import requests
import json
import urllib3
import smtplib
from email.mime.text import MIMEText

login = ''
password = ''
url = 'https://'

requests.packages.urllib3.disable_warnings()

#alert class. more to be added here. needs to support adding to/from,subject,message

class Alert:

    def __init__(self):
        self.recipient = ""
        self.sender = ""
        self.message = ""
        
    def updateRecipient(self,name):
        self.recipient = name

    def updateSender(self,name):
        self.sender = name

    def updateMessage(self,message):
        self.message = message
        
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

#going to be moved into the alert class
def sendMail():

    message = '''
    You have a scan that is starting soon!
    '''

    msg = MIMEText(message,'plain')
    msg['Subject'] = "scan starting soon"
    me = 'user@user.com'
    msg['From'] = me
    msg['To'] = me
    
    try:
        s = smtplib.SMTP('mailserver.com',25)
        s.send_message(msg) #sender,receiver,message
        print("sent email")
    except Exception as e:
        print(e)
        print("There was an error sending the email")

        
if __name__=='__main__':
    print("Getting logged into SecurityCenter")
    
    cookie,headers = getTokenCookie()
    print("got cookies and header information")
    
    sendMail()
    
            
