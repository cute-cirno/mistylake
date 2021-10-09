import re
from pydantic.types import Json
import requests
import rsa
import copy
import yaml
import os,json
import base64
import random

from typing_extensions import ParamSpec
from nonebot.adapters.cqhttp.message import Message
from nonebot.permission import SUPERUSER
from urllib3.exceptions import InsecureRequestWarning
from io import BytesIO
from Crypto.Cipher import AES
from bs4 import BeautifulSoup
from nonebot import on_command
from nonebot.typing import T_State
from nonebot.adapters import Event
from nonebot.adapters.cqhttp import Bot, MessageEvent, MessageSegment

cp = on_command('今日校园', priority=5)

requests.packages.urllib3.disable_warnings(InsecureRequestWarning)
proxies = {
#这里填上http代理地址
}



class Utils:
    def __init__(self):
        pass

    # 获取指定长度的随机字符

    @staticmethod
    def randString(length):
        baseString = "ABCDEFGHJKMNPQRSTWXYZabcdefhijkmnprstwxyz2345678"
        data = ''
        for i in range(length):
            data += baseString[random.randint(0, len(baseString) - 1)]
        return data

    # RSA加密的实现
    @staticmethod
    def encryptRSA(message, m, e):
        mm = int(m, 16)
        ee = int(e, 16)
        rsa_pubkey = rsa.PublicKey(mm, ee)
        crypto = Utils._encrypt_rsa(message.encode(), rsa_pubkey)
        return crypto.hex()

    @staticmethod
    def _encrypt_rsa(message, pub_key):
        keylength = rsa.common.byte_size(pub_key.n)
        padded = Utils._pad_for_encryption_rsa(message, keylength)
        payload = rsa.transform.bytes2int(padded)
        encrypted = rsa.core.encrypt_int(payload, pub_key.e, pub_key.n)
        block = rsa.transform.int2bytes(encrypted, keylength)
        return block

    @staticmethod
    def _pad_for_encryption_rsa(message, target_length):
        message = message[::-1]
        max_msglength = target_length - 11
        msglength = len(message)
        padding = b''
        padding_length = target_length - msglength - 3
        for i in range(padding_length):
            padding += b'\x00'
        return b''.join([b'\x00\x00', padding, b'\x00', message])

    # aes加密的实现
    @staticmethod
    def encryptAES(password, key):
        randStrLen = 64
        randIvLen = 16
        ranStr = Utils.randString(randStrLen)
        ivStr = Utils.randString(randIvLen)
        aes = AES.new(bytes(key, encoding='utf-8'), AES.MODE_CBC,
                      bytes(ivStr, encoding="utf8"))
        data = ranStr + password

        text_length = len(data)
        amount_to_pad = AES.block_size - (text_length % AES.block_size)
        if amount_to_pad == 0:
            amount_to_pad = AES.block_size
        pad = chr(amount_to_pad)
        data = data + pad * amount_to_pad

        text = aes.encrypt(bytes(data, encoding='utf-8'))
        text = base64.encodebytes(text)
        text = text.decode('utf-8').strip()
        return text


class TodayLoginService:
    # 初始化本地登录类
    def __init__(self, userInfo):
        self.username = userInfo['username']
        self.password = userInfo['password']
        self.session = requests.session()
        headers = {
            'User-Agent': 'Mozilla/5.0 (Linux; U; Android 8.1.0; zh-cn; BLA-AL00 Build/HUAWEIBLA-AL00) AppleWebKit/537.36 (KHTML, like Gecko) Version/4.0 Chrome/57.0.2987.132 MQQBrowser/8.9 Mobile Safari/537.36',
        }
        self.session.headers = headers
        self.login_url = 'http://cas.yangtzeu.edu.cn/authserver/login?service=https%3A%2F%2Fyangtzeu.campusphere.net%2Fiap%2FloginSuccess%3FsessionToken%3D716a63ab89384337adae72fcc9146878'
        self.host = ''
        self.login_host = 'http://cas.yangtzeu.edu.cn/'
        self.loginEntity = None
        self.type = 0
        self.needVerify = 0
        self.imgcode = ''

    # 通过url解析图片验证码
    def getCodeFromImg(self, imgUrl):
        response = self.session.get(imgUrl, verify=False)
        imgCode = "base64://" + \
            str(base64.b64encode(BytesIO(response.content).read()), encoding='utf-8')
        return(imgCode)

    # 判断是否需要验证码
    def getNeedCaptchaUrl(self):
        if self.type == 0:
            url = self.login_host + 'authserver/needCaptcha.html' + '?username=' + self.username
            flag = self.session.get(url, proxies=proxies, verify=False).text
            return 'false' != flag and 'False' != flag
        else:
            url = self.login_host + 'authserver/checkNeedCaptcha.htl' + \
                '?username=' + self.username
            flag = self.session.get(url, proxies=proxies, verify=False).json()
            return flag['isNeed']

    def login1(self):
        html = self.session.get(
            self.login_url, proxies=proxies, verify=False).text
        soup = BeautifulSoup(html, 'lxml')
        form = soup.select('#casLoginForm')
        if len(form) == 0:
            form = soup.select("#loginFromId")
            if len(form) == 0:
                raise Exception('出错啦！网页中没有找到casLoginForm')
            soup = BeautifulSoup(str(form[1]), 'lxml')
            self.type = 1
        # 填充数据
        self.params = {}
        form = soup.select('input')
        for item in form:
            if None != item.get('name') and len(item.get('name')) > 0:
                if item.get('name') != 'rememberMe':
                    if None == item.get('value'):
                        self.params[item.get('name')] = ''
                    else:
                        self.params[item.get('name')] = item.get('value')
        if self.type == 0:
            salt = soup.select("#pwdDefaultEncryptSalt")
        else:
            salt = soup.select("#pwdEncryptSalt")
        if len(salt) != 0:
            salt = salt[0].get('value')
        else:
            pattern = '\"(\w{16})\"'
            salt = re.findall(pattern, html)
            if (len(salt) == 1):
                salt = salt[0]
            else:
                salt = False
        self.params['username'] = self.username
        if not salt:
            self.params['password'] = self.password
        else:
            self.params['password'] = Utils.encryptAES(self.password, salt)
            if self.getNeedCaptchaUrl():
                self.needVerify = 1
                if self.type == 0:
                    imgUrl = self.login_host + 'authserver/captcha.html'
                    self.params['captchaResponse'] = self.getCodeFromImg(
                        self.session, imgUrl)
                else:
                    imgUrl = self.login_host + 'authserver/getCaptcha.htl'
                    imgcode = self.getCodeFromImg(imgUrl)
                    info = [self, self.params, self.needVerify]
                    return(imgcode, info)
        info = [self, self.params, self.needVerify]
        return(self.login2(None, self.params, self.needVerify), info)

    def login2(self, captchacode, params, needVerify):
        if needVerify:
            params['captcha'] = captchacode
        data = self.session.post(
            self.login_url, params=params, allow_redirects=False)
        # 如果等于302强制跳转，代表登陆成功
        if data.status_code == 302:
            jump_url = data.headers['Location']
            self.session.headers['Server'] = 'CloudWAF'
            res = self.session.get(jump_url, proxies=proxies, verify=False)
            if res.status_code == 200:
                print("登录成功")
                return 200
        elif data.status_code == 401:
            return 401


tds = TodayLoginService

path = os.path.abspath('.') + '/data/cpconfig.yml'
mbpath = os.path.abspath('.') + '/data/Tmblist.json'

@cp.handle()
async def main(bot: Bot, event: MessageEvent, state: T_State):
    state['userid'] = event.user_id
    await cp.send("请发送你的学号，例如:\n202012345")

@cp.got("username")
async def getusername(bot: Bot, event: MessageEvent, state: T_State):
    username = str(state['username'])
    await cp.send("请输入密码,不知道密码可以去\nhttp://  /authserver/login\n找回密码")

@cp.got("pwd")
async def getpwd(bot: Bot, event: MessageEvent, state: T_State):
    password = state['pwd']
    username = state['username']
    user = {'user': {'username': f'{username}', 'password': f'{password}'}}
    today = tds(user['user'])
    msg = ''
    statu_code, state['info'] = today.login1()
    if not state['info'][2]:
        msg += str(statu_code)
        if statu_code == 200:
            f = open(path, 'r', encoding='utf-8')
            file_data = f.read()
            config = yaml.load(file_data, Loader=yaml.FullLoader)
            raw_config = copy.deepcopy(config['users'][0])
            raw_config['user']['username'] = f'{username}'
            raw_config['user']['password'] = f'{password}'
            config['users'].append(raw_config)
            f.close()
            f1 = open(path, 'w', encoding='utf-8')
            yaml.dump(config, f1)
            mbjson = state['mbjson']
            mbjson['onwork'].append(int(username))
            with open(mbpath,'w',encoding='utf-8') as f2:
                json.dump(mbjson,f2)
            await cp.finish("验证通过，记录完毕")
        else:
            await cp.finish(msg + "账号或密码错误")
    else:
        img = MessageSegment.image(statu_code)
        msg = Message(img+"请输入验证码")
        await cp.send(img)


@cp.got("captchacode")
async def getV(bot: Bot, event: Event, state: T_State):
    captchacode = str(state['captchacode'])
    a = tds.login2(state['info'][0], captchacode,
                   state['info'][1], state['info'][2])
    if a == 200:
        await cp.finish("验证通过")
    else:
        await cp.finish("账号或密码错误")
