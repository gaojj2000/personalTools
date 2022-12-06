# _*_ coding:utf-8 _*_
# FileName: main.py
# IDE: PyCharm

# pip3 install pymysql fastapi[all] jinja2 python-multipart python-jose[cryptography] passlib[bcrypt] uvicorn[standard] pydantic[email] requests lxml beautifulsoup4==4.7.1

# 最快的Python异步I/O框架：Vibora【未圆满】
# uvicorn main:app --reload --port 8888【本地启动】
# nohup /www/server/panel/pyenv/bin/uvicorn main:app --host 10.0.16.8 --port 11111 > uvicorn.log 2>&1 &（pip3 install uvicorn【接近最快】）
# nohup /www/server/panel/pyenv/bin/daphne main:app -b 10.0.16.8 -p 11111 > daphne.log 2>&1 &（pip3 install daphne【较稳定，来自Django】）
# for pid in `ps -aux | grep -v grep | grep python3 | awk '{print $2}'`;do kill -9 $pid;done
# cat /dev/null > ~/.bash_history && history -c && exit

# 管理员账号：XXXXXXXXX   管理员密码：XXXXXXXXX
# 生成密码：password_crypt.hash(password)
# 校验密码：password_crypt.verify(plain_password, hashed_password)

import os.path
import re
import json
import time
import logging
from bs4 import BeautifulSoup
from passlib.context import CryptContext
from fastapi.responses import JSONResponse
from fastapi.encoders import jsonable_encoder
from starlette.requests import Request
from starlette.staticfiles import StaticFiles
from starlette.templating import Jinja2Templates
from starlette.middleware.cors import CORSMiddleware
from requests import (
    get,
    post,
    exceptions
)
from typing import (
    List,
    Union,
    Optional
)
from pydantic import (
    BaseModel,
    EmailStr
)
from datetime import (
    date,
    datetime,
    timedelta
)
from jose import (
    JWTError,
    jwt
)
from pymysql import (
    connect,
    cursors
)
from fastapi import (
    FastAPI,
    Form,
    Body,
    Depends,
    Response,
    HTTPException,
    status
)
from fastapi.security import (
    OAuth2PasswordBearer,
    OAuth2PasswordRequestForm
)

# 110.42.181.215【端口选择：666、888、999、1111、8888、9999、11111】（6666是非安全端口！！！【–explicitly-allowed-ports=6666,6667,6668 如果有多个端口请用逗号隔开】）
"""
不安全端口：
1,    // tcpmux
7,    // echo
9,    // discard
11,   // systat
13,   // daytime
15,   // netstat
17,   // qotd
19,   // chargen
20,   // ftp data
21,   // ftp access
22,   // ssh
23,   // telnet
25,   // smtp
37,   // time
42,   // name
43,   // nicname
53,   // domain
77,   // priv-rjs
79,   // finger
87,   // ttylink
95,   // supdup
101,  // hostriame
102,  // iso-tsap
103,  // gppitnp
104,  // acr-nema
109,  // pop2
110,  // pop3
111,  // sunrpc
113,  // auth
115,  // sftp
117,  // uucp-path
119,  // nntp
123,  // NTP
135,  // loc-srv /epmap
139,  // netbios
143,  // imap2
179,  // BGP
389,  // ldap
465,  // smtp+ssl
512,  // print / exec
513,  // login
514,  // shell
515,  // printer
526,  // tempo
530,  // courier
531,  // chat
532,  // netnews
540,  // uucp
556,  // remotefs
563,  // nntp+ssl
587,  // stmp?
601,  // ??
636,  // ldap+ssl
993,  // ldap+ssl
995,  // pop3+ssl
2049, // nfs
3659, // apple-sasl / PasswordServer
4045, // lockd
6000, // X11
6665, // Alternate IRC [Apple addition]
6666, // Alternate IRC [Apple addition]
6667, // Standard IRC [Apple addition]
6668, // Alternate IRC [Apple addition]
6669, // Alternate IRC [Apple addition]

http压力测试：
git clone https://github.com/wg/wrk.git
cd wrk
make
cp wrk /usr/local/bin/
wrk -t100 -c1000 --latency http://110.42.181.215:8080/【单核极限，多核可增加】
"""

headers = {"WWW-Authenticate": "Bearer", "Content-Type": "text/html;charset=utf-8"}  # 一般text/html返回的请求头

SECRET_KEY = 'be188f4fca3099678dfb0cbc95ff65a0c630d22500ed887c2480f81fed4309dd'  # openssl rand -hex 32
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 60 * 2
HEADERS = {
    "accept": "text/html,application/xhtml+xml,application/xml,;q=0.9,image/webp,image/apng,*/*;q=0.8;",
    "accept-encoding": "gzip, deflate, br",
    "accept-language": "zh-CN,zh;q=0.9,en;q=0.8",
    "referer": "https://user.qzone.qq.com",  # 获取日志需要 referer 字段，否则返回 403。
    "user-agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/66.0.3359.139 Safari/537.36"
}

if not os.path.exists('qqDataSave'):
    os.makedirs('qqDataSave')

app = FastAPI()
app.mount("/qq", StaticFiles(directory='qqDataSave'), name="qq")
app.mount("/html", StaticFiles(directory='html'), name="html")
app.mount("/js", StaticFiles(directory="html/js"), name="js")
app.mount("/img", StaticFiles(directory='html/img'), name="img")
app.mount("/file", StaticFiles(directory='html/file'), name="file")
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)
templates = Jinja2Templates(directory="html")
user_login = OAuth2PasswordBearer(tokenUrl="user_login")
admin_login = OAuth2PasswordBearer(tokenUrl="admin_login")
password_crypt = CryptContext(schemes=["bcrypt"], deprecated="auto")
UNAUTHORIZED = HTTPException(
    status_code=status.HTTP_401_UNAUTHORIZED,
    detail="您尚未登录或无此权限！",
    headers={"WWW-Authenticate": "Bearer"}
)
UNSUPPORTED_OPERATION = HTTPException(
    status_code=status.HTTP_400_BAD_REQUEST,
    detail="该操作未被定义！",
    headers={"WWW-Authenticate": "Bearer"}
)
MISSING_PARAMETERS = HTTPException(
    status_code=status.HTTP_400_BAD_REQUEST,
    detail="值缺失或值类型错误！",
    headers={"WWW-Authenticate": "Bearer"}
)


mysql = connect(
    user='root',
    password='XXXXXXXXX',
    host='localhost',
    database='gaojj',
    port=3306,
    charset='utf8mb4',
    cursorclass=cursors.SSDictCursor
)
cursor = mysql.cursor()
logging.basicConfig(filename='logs.log', format='%(asctime)s\t%(filename)s[line:%(lineno)d]\t%(levelname)s\t%(message)s')


class Admin(BaseModel):  # 管理员表
    admin_id: int = None  # 管理员编号
    admin_name: Optional[str] = None  # 管理员登录名【*】
    admin_password: Optional[str] = None  # 管理员登录密码


class User(BaseModel):  # 用户表
    user_id: int = None  # 用户编号
    user_name: Optional[str] = None  # 用户登录名【*】
    user_realname: Optional[str] = None  # 用户真实姓名
    user_password: Optional[str] = None  # 用户密码
    user_sex: Optional[str] = None  # 用户性别
    user_telephone: Optional[int] = None  # 用户电话
    user_email: Optional[EmailStr] = None  # 用户邮箱
    user_address: Optional[str] = None  # 用户地址
    disabled: Optional[date] = None  # 禁用用户（截止日期后解封，空则一直解封）


class Message(BaseModel):  # 留言表
    message_id: int = None  # 留言编号【*】
    message_body: Optional[str] = None  # 留言内容
    message_time: Optional[datetime] = None  # 留言时间
    message_author: Optional[str] = None  # 留言作者【*】


class Permission(BaseModel):  # 权限密码表
    id: int = None  # 权限编号
    user_name: Optional[str] = None  # 拥有者编号【*】
    content: Optional[str] = None  # 权限密码/使用生成文件
    used: Optional[int] = 0  # 是否已使用【*】


class Token(BaseModel):  # 标准token模型
    access_token: Optional[str] = None
    token_type: Optional[str] = None


def exec_sql(sql: str) -> list:  # 数据库——查
    cursor.execute(sql)
    res = cursor.fetchall()
    return list(res)


def commit_sql(sql: str) -> bool:  # 数据库——增删改
    try:
        cursor.execute(sql)
        mysql.commit()
        return True
    except BaseException as e:
        logging.exception(e)
        mysql.rollback()
        return False


def get_admin(admin_name: str) -> dict:  # 获取管理员信息
    admin = exec_sql(f'select * from admin where admin_name="{admin_name}";')
    if admin:
        return admin[0]
    return {}


def get_user(user_name: Optional[str] = None, user_telephone: Optional[int] = None) -> dict:  # 获取用户信息
    if user_name:
        user = exec_sql(f'select * from user where user_name="{user_name}";')
        if user:
            return user[0]
    if user_telephone:
        user = exec_sql(f'select * from user where user_telephone={user_telephone};')
        if user:
            return user[0]
    return {}


def get_message(message_id: Optional[Union[int, str]] = None, message_author: Optional[str] = None) -> list:  # 获取留言信息
    if message_id:
        message = exec_sql(f'select * from message where message_id={message_id};')
        if message:
            return message
    if message_author:
        message = exec_sql(f'select * from message where message_author={message_author};')
        if message:
            return message
    return [{}]


def get_permission(user_name: str, used: Optional[int] = 0) -> list:  # 获取权限信息
    per = exec_sql(f'select * from permission where user_name="{user_name}" and used={used};')
    if per:
        if used:
            return per
        else:
            return [p["value"] for p in per]
    return []


def check_user(user: User) -> str:  # 验证用户注册信息
    """
    :return: 详情：
        '0': 没有该用户，可以顺利注册用户
        '1': 已有该用户名，但未被禁用
        '2': 已有该用户手机号，但未被禁用
        '3': 已有该用户名，但被禁用
        '4': 已有该用户手机号，但被禁用
    """
    user1 = get_user(user_name=user.user_name)
    res = ''
    if user1:
        user = User(**user1)
        res += '1'
        if user.disabled:
            if time.mktime(time.strptime(str(user.disabled), '%Y-%m-%d')) > time.time():
                res += '3'
            else:
                commit_sql(f'update user set `disabled` = null  where `user_name` = "{user.user_name}";')
    user2 = get_user(user_telephone=user.user_telephone)
    if user2:
        user = User(**user2)
        res += '2'
        if user.disabled:
            if time.mktime(time.strptime(str(user.disabled), '%Y-%m-%d')) > time.time():
                res += '4'
            else:
                commit_sql(f'update user set `disabled` = null  where `user_name` = "{user.user_name}";')
    if not res:
        res = '0'
    return res


def check_permission(user: User, value: str) -> str:  # 验证权限信息
    p = get_permission(user_name=user.user_name)
    if value in p:
        return value
    return ''


def update_permission(user: User, value: str, content: str, new_value: str):  # 更新权限信息
    p = get_permission(user_name=user.user_name)
    if value in p:
        commit_sql(f'update permission set `used` = 1, `content` = "{content}", `value` = "{new_value}"  where `user_name` = "{user.user_name}" and `value` = "{value}";')


def create_access_token(data: dict, expires_delta: Optional[timedelta] = None) -> jwt.encode:  # 创建jwt令牌
    to_encode = data.copy()
    if expires_delta:
        expire = datetime.utcnow() + expires_delta
    else:
        expire = datetime.utcnow() + timedelta(minutes=30)
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt


async def get_current_admin(token: str = Depends(admin_login)) -> Admin:  # 解码jwt令牌并获取当前管理员信息
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        admin_name: str = payload.get("gao_jj")
        if admin_name is None:
            raise UNAUTHORIZED
    except JWTError:
        raise UNAUTHORIZED
    admin = get_admin(admin_name)
    if admin is None:
        raise UNAUTHORIZED
    return Admin(**admin)


async def get_current_user(token: str = Depends(user_login)) -> User:  # 解码jwt令牌并获取当前用户信息
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        user_name: str = payload.get("gjj")
        if user_name is None:
            raise UNAUTHORIZED
    except JWTError:
        raise UNAUTHORIZED
    user = get_user(user_name)
    if user is None:
        raise UNAUTHORIZED
    if not os.path.exists(f'qqDataSave/{user_name}'):
        os.makedirs(f'qqDataSave/{user_name}')
    return User(**user)


@app.get('/', include_in_schema=False)
def index(request: Request) -> templates.TemplateResponse:
    return templates.TemplateResponse(
        name='index.html',
        context={'request': request},
        status_code=status.HTTP_200_OK
    )


@app.get('/admin.html', include_in_schema=False)
def admin_html(request: Request) -> Response:
    return templates.TemplateResponse(
        name='admin.html',
        context={'request': request},
        status_code=status.HTTP_200_OK
    )


@app.get('/user.html', include_in_schema=False)
def user_html(request: Request) -> templates.TemplateResponse:
    return templates.TemplateResponse(
        name='user.html',
        context={'request': request},
        status_code=status.HTTP_200_OK
    )


@app.get('/permission.html', include_in_schema=False)
def user_html(request: Request) -> templates.TemplateResponse:
    return templates.TemplateResponse(
        name='permission.html',
        context={'request': request},
        status_code=status.HTTP_200_OK
    )


@app.get('/permission', include_in_schema=True, summary='获取可用的权限值')
def permission(response: Response, current_user: User = Depends(get_current_user)) -> Response:
    """
    ## 参数：
        无
    ## 需要
        用户验证
    ## 返回
        text/html
    """
    if current_user.user_name:
        response.headers.append(key="Access-Control-Allow-Origin", value="*")
        response.headers.append(key="contentType", value="text/html;charset=utf-8")
        return Response(
            status_code=status.HTTP_200_OK,
            content=f"<font style=\"color: red;\">{'<br />'.join(['当前拥有的权限密码（一个只能使用一次，获取数据成功后抵扣）：'] + get_permission(user_name=current_user.user_name))}</font>",
            media_type='text/html',
            headers=headers
        )
    raise UNAUTHORIZED


@app.post('/admin_login', include_in_schema=True, summary='管理员登录')
def login_admin(form_data: OAuth2PasswordRequestForm = Depends()) -> JSONResponse:
    """
    ## 参数：
        username: 管理员账户【字符串】
        password: 管理员密码【字符串】
    ## 需要
        无
    ## 返回
        application/json
    """
    admin_name = form_data.username
    admin_password = form_data.password
    current_admin: Admin = Admin(**get_admin(admin_name))
    if current_admin.admin_name:
        if password_crypt.verify(admin_password, current_admin.admin_password):
            access_token_expires = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
            access_token = create_access_token(data={"gao_jj": current_admin.admin_name}, expires_delta=access_token_expires)
            return JSONResponse(
                status_code=status.HTTP_200_OK,
                content=jsonable_encoder(Token(**{"access_token": access_token, "token_type": "bearer"})),
                headers=headers
            )
        else:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail=f"管理员 {admin_name} 存在，但密码错误！",
                headers=headers
            )
    raise HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail=f"管理员 {admin_name} 不存在！",
        headers=headers
    )


@app.post('/user_login', include_in_schema=True, summary='用户登录')
def login_user(form_data: OAuth2PasswordRequestForm = Depends()) -> JSONResponse:
    """
    ## 参数：
        username: 用户账户【字符串】
        password: 用户密码【字符串】
    ## 需要
        无
    ## 返回
        application/json
    """
    user_name = form_data.username
    user_password = form_data.password
    current_user: User = User(**get_user(user_name))
    if current_user.user_name:
        if current_user.disabled:
            if time.mktime(time.strptime(str(current_user.disabled), '%Y-%m-%d')) > time.time():
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail=f"用户 {user_name} 存在，但该用户被管理员禁用！解封日期：{current_user.disabled}",
                    headers=headers
                )
            else:
                commit_sql(f'update user set `disabled` = null  where `user_name` = "{current_user.user_name}";')
        if password_crypt.verify(user_password, current_user.user_password):
            access_token_expires = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
            access_token = create_access_token(data={"gjj": current_user.user_name}, expires_delta=access_token_expires)
            return JSONResponse(
                status_code=status.HTTP_200_OK,
                content=jsonable_encoder(Token(**{"access_token": access_token, "token_type": "bearer"})),
                headers=headers
            )
        else:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail=f"用户 {user_name} 存在，但密码错误！",
                headers=headers
            )
    raise HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail=f"用户 {user_name} 不存在！",
        headers=headers
    )


@app.get('/admin', response_model=Admin, include_in_schema=True, summary='验证并返回管理员信息')
def get_admin_info(response: Response, current_admin: Admin = Depends(get_current_admin)) -> Admin:
    """
    ## 参数：
        无
    ## 需要
        管理员验证
    ## 返回
        dict
    """
    response.headers.append(key="Access-Control-Allow-Origin", value="*")
    if current_admin.admin_name:
        return current_admin
    raise UNAUTHORIZED


@app.post('/admin_update', include_in_schema=True, summary='修改管理员信息')
async def admin_update(response: Response, admin_password: str = Form(...), current_admin: Admin = Depends(get_current_admin)) -> Response:
    """
    ## 参数：
        admin_password: 管理员密码【字符串】
    ## 需要
        管理员验证
    ## 返回
        text/html
    """
    response.headers.append(key="Access-Control-Allow-Origin", value="*")
    if current_admin.admin_name:
        res = commit_sql(f'update admin set admin_password="{admin_password}" where admin_name="{current_admin.admin_name}";')
        if res:
            return Response(
                status_code=status.HTTP_200_OK,
                content=f"修改管理员 {current_admin.admin_name} 成功！",
                media_type='text/html',
                headers=headers
            )
        else:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"修改管理员 {current_admin.admin_name} 失败！",
                headers=headers
            )
    raise UNAUTHORIZED


@app.post('/admin_functions', include_in_schema=True, summary='管理员操作')
def admin_functions(response: Response, function: str = Form(...), current_admin: Admin = Depends(get_current_admin)) -> Response:
    """
    ## 参数：
        function: 操作字符串【字符串】
            disable user XXXX-XX-XX: 禁用用户user到XXXX年XX月XX日
            enable user1, user2: 解除禁用用户user1，user2
            permission user1, user2：给用户user1，user2创建一次操作权限
    ## 需要
        管理员验证
    ## 返回
        text/html
    """
    response.headers.append(key="Access-Control-Allow-Origin", value="*")
    sql = ''
    functions = function.split(' ')
    if not functions:
        raise UNSUPPORTED_OPERATION
    elif functions[0] == 'disable':
        if len(functions) == 2:
            if get_user(user_name=functions[1]):
                try:
                    limit_time = time.strftime("%Y-%m-%d", time.localtime(time.mktime(time.strptime(functions[2], '%Y-%m-%d'))))
                    if time.mktime(time.strptime(functions[2], '%Y-%m-%d')) > time.time():
                        sql += f'update user set `disabled` = "{limit_time}"  where `user_name` = "{functions[1]}";'
                    else:
                        sql += f'update user set `disabled` = null  where `user_name` = "{functions[1]}";'
                except ValueError:
                    raise MISSING_PARAMETERS
        raise MISSING_PARAMETERS
    elif functions[0] == 'enable':
        if not functions[1:]:
            raise MISSING_PARAMETERS
        else:
            for user in functions[1:]:
                if get_user(user_name=user):
                    sql += f'update user set `disabled` = null  where `user_name` = "{user}";'
    elif functions[0] == 'permission':
        if not functions[1:]:
            raise MISSING_PARAMETERS
        else:
            for user in functions[1:]:
                if get_user(user_name=user):
                    value = ''.join(__import__('random').choices(list(__import__('string').ascii_letters), k=__import__('random').randint(10, 15)))
                    sql += f'insert into permission (`user_name`, `value`, `used`) values ("{user}", "{value}", 0);'
    else:
        raise UNSUPPORTED_OPERATION
    if current_admin.admin_name:
        if commit_sql(sql):
            return Response(
                status_code=status.HTTP_200_OK,
                content="操作执行成功！",
                media_type='text/html',
                headers=headers
            )
        else:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="操作执行失败！",
                headers=headers
            )
    raise UNAUTHORIZED


@app.get('/user', response_model=User, include_in_schema=True, summary='验证并返回用户信息')
def get_user_info(response: Response, current_user: User = Depends(get_current_user)) -> User:
    """
    ## 参数：
        无
    ## 需要
        用户验证
    ## 返回
        dict
    """
    response.headers.append(key="Access-Control-Allow-Origin", value="*")
    if current_user.user_name:
        return current_user
    raise UNAUTHORIZED


@app.post('/user_add', include_in_schema=True, summary='用户注册')
async def user_add(response: Response, user_name: str = Form(...), user_realname: str = Form(...), user_password: str = Form(...), user_sex: str = Form(...),
                   user_telephone: int = Form(...), user_email: EmailStr = Form(...), user_address: str = Form(...)) -> Response:
    """
    ## 参数：
        user_name: 用户登录名【字符串】
        user_realname: 用户真实姓名【字符串】
        user_password: 用户密码【字符串】
        user_sex: 用户性别【字符串】
        user_telephone: 用户电话【整型】
        user_email: 用户邮箱【邮箱字符串】
        user_address: 用户地址【字符串】
    ## 需要
        无
    ## 返回
        text/html
    """
    response.headers.append(key="Access-Control-Allow-Origin", value="*")
    response.headers.append(key="contentType", value="text/html;charset=utf-8")
    judge = check_user(User(user_name=user_name, user_telephone=user_telephone))
    detail = ''
    ok = False
    if '1' in judge:
        detail += '已有该用户名，'
    elif '2' in judge:
        detail += '已有该手机号用户，'
    if '0' in judge:
        res = commit_sql(f'insert into user (`user_name`, `user_realname`, `user_password`, `user_sex`, `user_telephone`, `user_email`, `user_address`)'
                         f' values ("{user_name}", "{user_realname}", "{password_crypt.hash(user_password)}", "{user_sex}", "{user_telephone}", "{user_email}", "{user_address}");')
        if res:
            if not os.path.exists(f'qqDataSave/{user_name}'):
                os.makedirs(f'qqDataSave/{user_name}')
            open(f'qqDataSave/{user_name}/{user_password}', 'w').write('')
            ok = True
            detail += f'创建用户 {user_name} 成功！'
        else:
            detail += f'创建用户 {user_name} 失败！'
    elif '1' in judge:
        detail += '用户名不可被更改！'
    elif '2' in judge:
        res = commit_sql(f'update user set `user_realname` = "{user_realname}", `user_password` = "{password_crypt.hash(user_password)}", '
                         f'`user_sex` = "{user_sex}", `user_telephone` = {user_telephone}, `user_email` = "{user_email}", '
                         f'`user_address` = "{user_address}" where `user_name` = "{user_name}";')
        if res:
            if not os.path.exists(f'qqDataSave/{user_name}'):
                os.makedirs(f'qqDataSave/{user_name}')
            open(f'qqDataSave/{user_name}/{user_password}', 'w').write('')
            ok = True
            detail += f'更新原用户 {user_name} 成功！'
        else:
            detail += f'更新原用户 {user_name} 失败！'
    elif '3' in judge or '4' in judge:
        detail += '但该用户被禁用！'
    if ok:
        return Response(
            status_code=status.HTTP_201_CREATED,
            content=detail,
            media_type='text/html',
            headers=headers
        )
    else:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=detail,
            headers=headers
        )


@app.post('/user_update', include_in_schema=True, summary='修改用户信息')
async def user_update(response: Response, user_name: str = Form(...), user_realname: str = Form(...), user_password: str = Form(...),
                      user_sex: str = Form(...), user_telephone: int = Form(...), user_email: EmailStr = Form(...),
                      user_address: str = Form(...), current_user: User = Depends(get_current_user)) -> Response:
    """
    ## 参数：
        user_name: 用户登录名【字符串】
        user_realname: 用户真实姓名【字符串】
        user_password: 用户密码【字符串】
        user_sex: 用户性别【字符串】
        user_telephone: 用户电话【整型】
        user_email: 用户邮箱【邮箱字符串】
        user_address: 用户地址【字符串】
    ## 需要
        用户验证
    ## 返回
        text/html
    """
    response.headers.append(key="Access-Control-Allow-Origin", value="*")
    response.headers.append(key="contentType", value="text/html;charset=utf-8")
    if current_user.user_name:
        res = commit_sql(f'update user set `user_realname` = "{user_realname}", `user_password` = "{password_crypt.hash(user_password)}", '
                         f'`user_sex` = "{user_sex}", `user_telephone` = {user_telephone}, `user_email` = "{user_email}", '
                         f'`user_address` = "{user_address}" where `user_name` = "{user_name}";')
        if res:
            return Response(
                status_code=status.HTTP_200_OK,
                content=f"修改用户 {user_name} 信息成功！",
                media_type='text/html',
                headers=headers
            )
        else:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"修改用户 {user_name} 信息失败！",
                headers=headers
            )
    raise UNAUTHORIZED


@app.post('/user_delete', include_in_schema=True, summary='注销用户')
async def user_delete(response: Response, current_user: User = Depends(get_current_user)) -> Response:
    """
    ## 参数：
        无
    ## 需要
        用户验证
    ## 返回
        text/html
    """
    response.headers.append(key="Access-Control-Allow-Origin", value="*")
    response.headers.append(key="contentType", value="text/html;charset=utf-8")
    if current_user.user_name:
        if commit_sql(f'delete from user where user_id={current_user.user_id};'):
            return Response(
                status_code=status.HTTP_200_OK,
                content=f"您的用户 {current_user.user_name} 注销成功！",
                media_type='text/html',
                headers=headers
            )
        else:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"您的用户 {current_user.user_name} 注销失败！",
                headers=headers
            )
    raise UNAUTHORIZED


@app.get('/message', response_model=List[Message], include_in_schema=True, summary='获取留言信息')
def get_message_info(response: Response, current_user: User = Depends(get_current_user)) -> List[Message]:
    """
    ## 参数：
        无
    ## 需要
        用户验证
    ## 返回
        list[dict]
    """
    response.headers.append(key="Access-Control-Allow-Origin", value="*")
    response.headers.append(key="contentType", value="application/json;charset=utf-8")
    if current_user.user_name:
        message: List[Message] = [Message(**g) for g in get_message(message_author=current_user.user_name)]
        if message[0]:
            return message
        else:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="该用户没有任何留言！",
                headers=headers,
            )
    raise UNAUTHORIZED


@app.post('/message_add', include_in_schema=True, summary='添加留言信息')
async def message_add(response: Response, message_body: str = Form(...), current_user: User = Depends(get_current_user)) -> Response:
    """
    ## 参数：
        message_body: 留言内容【字符串】
    ## 需要
        用户验证
    ## 返回
        text/html
    """
    response.headers.append(key="Access-Control-Allow-Origin", value="*")
    response.headers.append(key="contentType", value="text/html;charset=utf-8")
    if current_user.user_name:
        res = commit_sql(f'insert into message (`message_body`, `message_time`, `message_author`) values'
                         f' ("{message_body}", "{datetime.now()}", "{current_user.user_name}");')
        if res:
            return Response(
                status_code=status.HTTP_201_CREATED,
                content=f"创建留言 {message_body[:6]}... 成功！",
                media_type='text/html',
                headers=headers
            )
        else:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"创建留言 {message_body[:6]}... 失败！",
                headers=headers
            )
    raise UNAUTHORIZED


@app.post('/message_update', include_in_schema=True, summary='修改留言信息')
async def message_update(response: Response, message_id: Union[int, str] = Form(...), message_body: str = Form(...), current_user: User = Depends(get_current_user)) -> Response:
    """
    ## 参数：
        message_id: 留言id【整型或整型字符串】
        message_body: 留言内容【字符串】
    ## 需要
        用户验证
    ## 返回
        text/html
    """
    response.headers.append(key="Access-Control-Allow-Origin", value="*")
    response.headers.append(key="contentType", value="text/html;charset=utf-8")
    if current_user.user_name:
        res = commit_sql(f'update message set `message_body` = "{message_body}"  where `message_id` = {message_id};')
        if res:
            return Response(
                status_code=status.HTTP_200_OK,
                content=f"修改留言 {message_body[:6]}... 成功！",
                media_type='text/html',
                headers=headers
            )
        else:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"修改留言 {message_body[:6]}... 失败！",
                headers=headers
            )
    raise UNAUTHORIZED


@app.post('/message_delete', include_in_schema=True, summary='删除留言信息')
async def message_delete(response: Response, message_id: Union[int, str] = Body(...), current_user: User = Depends(get_current_user)) -> Response:
    """
    ## 参数：
        message_id: 留言id【整型或整型字符串】
    ## 需要
        用户验证
    ## 返回
        text/html
    """
    response.headers.append(key="Access-Control-Allow-Origin", value="*")
    response.headers.append(key="contentType", value="text/html;charset=utf-8")
    if current_user.user_name:
        message = get_message(message_id=message_id)
        if message[0]:
            message = Message(**message[0])
            if commit_sql(f'delete from message where message_id={message_id};'):
                return Response(
                    status_code=status.HTTP_200_OK,
                    content=f"删除留言 {message.message_body[:6]}... 成功！",
                    media_type='text/html',
                    headers=headers
                )
            else:
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail=f"删除留言 {message.message_body[:6]}... 失败！",
                    headers=headers
                )
        else:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"留言ID {message_id} 不存在！",
                headers=headers
            )
    raise UNAUTHORIZED


def str_dump(data: list) -> str:
    rows = 0
    all_string = ''
    chinese = [0] * len(data[0])
    length = [0] * len(data[0])
    if len(set([len(r) for r in data])) != 1:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail='格式不正确！',
            headers=headers
        )
    for row in data:
        if rows < len(row):
            rows = len(row)
        for col in range(len(row)):
            for r in str(row[col]).split('\n'):
                if length[col] < len(r):
                    length[col] = len(r)
                if chinese[col] < len(''.join(re.findall(r'[\u4e00-\u9fa5，。！？（）【】［］《》－]+', r))):
                    chinese[col] = len(''.join(re.findall(r'[\u4e00-\u9fa5，。！？（）【】［］《》－]+', r)))
    length = [le + c for le, c in zip(length, chinese)]
    temp = ''
    for le in range(len(length)):
        temp += '+' + '-' * (length[le] + 2)
    all_string += temp + '+\n'
    for row in data:
        string = '|'
        for le in range(len(length)):
            string += '{: ^' + str(length[le] + 2 - len(''.join(re.findall(r'[\u4e00-\u9fa5，。！？（）【】［］《》－]+', str(row[le]))))) + '}|'
        all_string += string.format(*row) + '\n' + temp + '+\n'
    return all_string.strip('\n')


@app.post('/dump', include_in_schema=True, summary='带边框线格式化表格')
def dump(response: Response, data: str = Body(...)) -> Response:
    """
    ## 参数：
        data: 表格数据【双层字符串列表】
    ## 需要
        无
    ## 返回
        text/html
    """
    response.headers.append(key="Access-Control-Allow-Origin", value="*")
    response.headers.append(key="contentType", value="text/html;charset=utf-8")
    data = eval(data)["data"]
    return Response(
        status_code=status.HTTP_200_OK,
        content=str_dump(data),
        media_type='text/html',
        headers=headers
    )


def get_url(url: str, params: dict = None, retry: int = 3, cookie: str = None, header: dict = None) -> get:
    for _ in range(retry):
        try:
            r = get(url, headers=header, params=params, cookies={"cookie": cookie}, timeout=10)
            if r.ok:
                return r
        except exceptions.ConnectionError:
            logging.exception('Connection refused by ' + url)
        except exceptions.ReadTimeout:
            logging.exception('Connection timeout by ' + url)
    return None


def post_url(url: str, data: dict = None, retry: int = 3, cookie: str = None, header: dict = None) -> post:
    for _ in range(retry):
        try:
            r = post(url, headers=header, data=data, cookies={"cookie": cookie}, timeout=10)
            if r.ok:
                return r
        except exceptions.ConnectionError:
            logging.exception('Connection refused by ' + url)
    return None


def parse_cookies(cookies: str) -> dict:
    cookies_dict = {}
    for c in cookies.replace(' ', '').split(';'):
        try:
            cookies_dict[c.split('=')[0]] = c.split('=')[1]
        except IndexError:
            cookies_dict[c.split('=')[0]] = ''
    if "" in cookies_dict:
        del cookies_dict[""]
    return cookies_dict


def parse_json(text: str) -> json.loads:
    return json.loads(text[text.find('{'): text.rfind('}') + 1])


def judge_json(response_json: dict) -> str:
    if response_json["code"]:
        if response_json["message"] in ["该条内容已被删除", "空间未开通"]:
            return response_json["message"]
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=response_json["message"],
            headers=headers
        )
    else:
        return ''


@app.post('/qq_birth', include_in_schema=True, summary='获取QQ创号信息')
async def qq_birth(response: Response, fun: str = Form(...), cookie: str = Form(...), current_user: User = Depends(get_current_user)) -> JSONResponse:
    """
    ## 参数：
        cookie: cookie数据【需要 https://qun.qq.com/ 的 cookie 值】
    ## 需要
        用户验证
    ## 返回
        text/html
    """
    response.headers.append(key="Access-Control-Allow-Origin", value="*")
    response.headers.append(key="contentType", value="text/html;charset=utf-8")
    if current_user.user_name:
        if not check_permission(current_user, fun):
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail='无此操作密码或操作密码已被使用！',
                headers=headers
            )
        if not os.path.exists(f'qqDataSave/{current_user.user_name}/{get_qq_from_cookie(cookie)}'):
            os.makedirs(f'qqDataSave/{current_user.user_name}/{get_qq_from_cookie(cookie)}')
        if not os.path.exists(f'qqDataSave/{current_user.user_name}/{get_qq_from_cookie(cookie)}/qun.txt'):
            open(f'qqDataSave/{current_user.user_name}/{get_qq_from_cookie(cookie)}/qun.txt', 'w').write('')
        header = {
            "Host": "ti.qq.com",
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,image/sharpp,image/apng,image/tpg,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9",
            "Q-UA2": "QV=3&PL=ADR&PR=QQ&PP=com.tencent.mobileqq&PPVN=8.8.33&TBSVC=44090&CO=BK&COVC=045814&PB=GE&VE=GA&DE=PHONE&CHID=0&LCID=9422&MO= PCNM00 &RL=1080*2264&OS=11&API=30",
            "Q-GUID": "db2c3b0e325b1f326f12cd1613b788cb",
            "Q-QIMEI": "a00000a572c97d",
            "QIMEI36": "9811f76dbe3853041596aaed100017e1491a",
            "Q-Auth": "31045b957cf33acf31e40be2f3e71c5217597676a9729f1b",
            "User-Agent": 'Mozilla/5.0 (Linux; Android 11; PCNM00 Build/RKQ1.200903.002; wv) AppleWebKit/537.36 (KHTML, like Gecko) Version/4.0 Chrome/89.0.4389.72 MQQBrowser/6.2 TBS/045814 Mobile Safari/537.36 V1_AND_SQ_8.8.33_2150_YYB_D A_8083300 QQ/8.8.33.6300 NetType/WIFI WebP/0.3.0 Pixel/1080 StatusBarHeight/96 SimpleUISwitch/0 QQTheme/1015266 InMagicWin/0 StudyMode/0 CurrentMode/0 CurrentFontScale/1.0'
        }
        url = 'https://ti.qq.com/qq20th?_wv=16777216&_wwv=132&ADTAG=qq.fri'
        for _ in range(10):
            res = get_url(url, header=header, cookie=cookie)
            if res:
                logging.info('状态码：200，正在检查数据！')
                soup = BeautifulSoup(res.text, 'lxml')
                for script in soup.find_all('script'):
                    if 'window.syncData' in script.text:
                        text = parse_json(script.text)
                        if cookie not in open(f'qqDataSave/{current_user.user_name}/{get_qq_from_cookie(cookie)}/qun.txt', 'r', encoding='utf-8').read():
                            open(f'qqDataSave/{current_user.user_name}/{get_qq_from_cookie(cookie)}/qun.txt', 'a', encoding='utf-8').write(f'{cookie}\n\n')
                        open(f'qqDataSave/{current_user.user_name}/{get_qq_from_cookie(cookie)}/qq_birth.json', 'w', encoding='utf-8').write(json.dumps(text, indent=4, ensure_ascii=False))
                        update_permission(user=current_user, value=fun, content='qq_birth.json', new_value=get_qq_from_cookie(cookie))
                        return JSONResponse(
                            status_code=status.HTTP_200_OK,
                            content=f'您的注册之日：<font style="color: red;">{time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(text["register_time"]))}</font>，您已创号 <font style="color: red;">{int(time.time() - text["register_time"]) // 3600 // 24}</font> 日！',
                            headers=headers
                        )
                else:
                    time.sleep(1)
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail='请检查cookie是否是从 https://qun.qq.com/ 获取的，请尝试重新登录重新获取cookie值！',
            headers=headers
        )
    raise UNAUTHORIZED


def parse_parameters(string: str) -> dict:
    parameters = {}
    string = string.strip().replace(' ', '')
    if ':' not in string and '&' in string:
        for _ in string.split('&'):
            try:
                parameters[_.split('=')[0]] = _.split('=')[1]
            except IndexError:
                parameters[_.split('=')[0]] = ''
    else:
        for _ in string.split('\n'):
            _ = _.strip()
            try:
                parameters[_.split(':')[0]] = _.split(':')[1]
            except IndexError:
                parameters[_.split(':')[0]] = ''
    return parameters


def get_qq_from_cookie(cookie: str) -> str:
    return str(int(parse_cookies(cookie)["p_uin"][1:]))


def get_gtk_from_cookie(cookie: str) -> str:
    t = 5381
    for cc in parse_cookies(cookie)["p_skey"]:
        t += (t << 5) + ord(cc)
    return str(t & 2147483647)


def get_bkn_from_cookie(cookie: str) -> str:
    t = 5381
    for cc in parse_cookies(cookie)["skey"]:
        t += (t << 5) + ord(cc)
    return str(t & 2147483647)


def get_muid_from_cookie(cookie: str) -> str:
    return parse_cookies(cookie)["muid"]


@app.post('/top200', include_in_schema=True, summary='获取前200位好友的亲密度关系')
async def top200_friend_ship(response: Response, fun: str = Form(...), cookie: str = Form(...), do: int = Form(...), current_user: User = Depends(get_current_user)) -> JSONResponse:
    """
    ## 参数：
        cookie: cookie数据【需要 https://user.qzone.qq.com/ 的 cookie 值】
        do: 我在意谁(do: 1)；谁在意我(do: 2)【需要 https://user.qzone.qq.com/ 的 cookie 值】
    ## 需要
        用户验证
    ## 返回
        list[list]  【'排序', 'QQ号', '备注', '亲密度', '特别关心'】
    """
    response.headers.append(key="Access-Control-Allow-Origin", value="*")
    response.headers.append(key="contentType", value="application/json;charset=utf-8")
    if current_user.user_name:
        if not check_permission(current_user, fun):
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail='无此操作密码或操作密码已被使用！',
                headers=headers
            )
        if not os.path.exists(f'qqDataSave/{current_user.user_name}/{get_qq_from_cookie(cookie)}'):
            os.makedirs(f'qqDataSave/{current_user.user_name}/{get_qq_from_cookie(cookie)}')
        if not os.path.exists(f'qqDataSave/{current_user.user_name}/{get_qq_from_cookie(cookie)}/space.txt'):
            open(f'qqDataSave/{current_user.user_name}/{get_qq_from_cookie(cookie)}/space.txt', 'w').write('')
        url = "https://user.qzone.qq.com/proxy/domain/r.qzone.qq.com/cgi-bin/tfriend/friend_ship_manager.cgi"
        parameters = parse_parameters("""
            uin: 
            do: 
            rd: 
            fupdate: 1
            clean: 1
            g_tk: 
        """)
        parameters["uin"] = get_qq_from_cookie(cookie)
        parameters["do"] = str(do)
        parameters["rd"] = str(__import__('random').random())
        parameters["g_tk"] = get_gtk_from_cookie(cookie)
        res = get_url(url, params=parameters, header=HEADERS, cookie=cookie).text
        js = parse_json(res)
        res = judge_json(js)
        if not res:
            friend_ship = [['排序', 'QQ号', '备注', '亲密度', '特别关心']]
            for _ in js["data"]["items_list"]:
                friend_ship.append([_["index"], _["uin"], _["name"], _["score"], _["special_flag"] == "1" and "是" or "否"])
            if cookie not in open(f'qqDataSave/{current_user.user_name}/{get_qq_from_cookie(cookie)}/space.txt', 'r', encoding='utf-8').read():
                open(f'qqDataSave/{current_user.user_name}/{get_qq_from_cookie(cookie)}/space.txt', 'a', encoding='utf-8').write(f'{cookie}\n\n')
            open(f'qqDataSave/{current_user.user_name}/{get_qq_from_cookie(cookie)}/top200_{do}.json', 'w', encoding='utf-8').write(json.dumps(friend_ship, indent=4, ensure_ascii=False))
            update_permission(user=current_user, value=fun, content=f'top200_{do}.json', new_value=get_qq_from_cookie(cookie))
            return JSONResponse(
                status_code=status.HTTP_200_OK,
                content=friend_ship,
                headers=headers
            )
        else:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=res + '，请检查cookie是否是从 https://user.qzone.qq.com/ 获取的，请尝试重新登录重新获取cookie值！',
                headers=headers
            )
    raise UNAUTHORIZED


def str_time(int_time: int = None, ymd: bool = True, hms: bool = False) -> time.strftime:
    assert int_time is None or isinstance(int_time, int), '时间戳存在时必须为整数！'
    if ymd and hms:
        return time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(int_time))
    if ymd:
        return time.strftime("%Y-%m-%d", time.localtime(int_time))
    if hms:
        return time.strftime("%H:%M:%S", time.localtime(int_time))
    return None


@app.post('/friend', include_in_schema=True, summary='获取目标QQ好友的详细信息')
async def one_friend_ship(response: Response, fun: str = Form(...), cookie: str = Form(...), passive: str = Form(...), current_user: User = Depends(get_current_user)) -> JSONResponse:
    """
    ## 参数：
        cookie: cookie数据【需要 https://user.qzone.qq.com/ 的 cookie 值】
        passive: 目标QQ好友【非自身、仅限好友而不是任何人】
    ## 需要
        用户验证
    ## 返回
        dict  【双向亲密度、加好友日期、加好友天数、共有的群】
    """
    response.headers.append(key="Access-Control-Allow-Origin", value="*")
    response.headers.append(key="contentType", value="application/json;charset=utf-8")
    if current_user.user_name:
        if not check_permission(current_user, fun):
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail='无此操作密码或操作密码已被使用！',
                headers=headers
            )
        if not os.path.exists(f'qqDataSave/{current_user.user_name}/{get_qq_from_cookie(cookie)}'):
            os.makedirs(f'qqDataSave/{current_user.user_name}/{get_qq_from_cookie(cookie)}')
        if not os.path.exists(f'qqDataSave/{current_user.user_name}/{get_qq_from_cookie(cookie)}/space.txt'):
            open(f'qqDataSave/{current_user.user_name}/{get_qq_from_cookie(cookie)}/space.txt', 'w').write('')
        if get_qq_from_cookie(cookie) == passive:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail='亲密度关系必须是两个不同的QQ号！',
                headers=headers
            )
        res = {}
        url = "https://user.qzone.qq.com/proxy/domain/r.qzone.qq.com/cgi-bin/friendship/cgi_friendship"
        parameters = parse_parameters("""
            activeuin: 
            passiveuin: 
            situation: 1
            isCalendar: 1
            g_tk: 
        """)
        parameters["g_tk"] = get_gtk_from_cookie(cookie)
        parameters["activeuin"] = get_qq_from_cookie(cookie)
        parameters["passiveuin"] = passive
        r = get_url(url, params=parameters, header=HEADERS, cookie=cookie).text
        js = parse_json(r)
        r = judge_json(js)
        if not r:
            if js["data"]["isFriend"] != 1:
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail=f'{get_qq_from_cookie(cookie)} 和 {passive} 不是好友！',
                    headers=headers
                )
            start = str_time(js["data"]["addFriendTime"])
            differ = int((time.time() - js["data"]["addFriendTime"]) / 3600 / 24)
            res[f"{get_qq_from_cookie(cookie)}->{passive}"] = {
                "亲密度": int(js["data"]["intimacyScore"]),
                "加好友日期": start,
                "加好友天数": differ,
                "共有的群": [_["name"] for _ in js["data"]["common"]["group"]]
            }
        else:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=r + '，请检查cookie是否是从 https://user.qzone.qq.com/ 获取的，请尝试重新登录重新获取cookie值！',
                headers=headers
            )
        parameters["activeuin"] = passive
        parameters["passiveuin"] = get_qq_from_cookie(cookie)
        r = get_url(url, params=parameters, header=HEADERS, cookie=cookie).text
        js = parse_json(r)
        r = judge_json(js)
        if not r:
            if js["data"]["isFriend"] != 1:
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail=f'{get_qq_from_cookie(cookie)} 和 {passive} 不是好友！',
                    headers=headers
                )
            start = str_time(js["data"]["addFriendTime"])
            differ = int((time.time() - js["data"]["addFriendTime"]) / 3600 / 24) + 2
            res[f"{passive}->{get_qq_from_cookie(cookie)}"] = {
                "亲密度": int(js["data"]["intimacyScore"]),
                "加好友日期": start,
                "加好友天数": differ,
                "共有的群": [_["name"] for _ in js["data"]["common"]["group"]]
            }
        else:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=r + '，请检查cookie是否是从 https://user.qzone.qq.com/ 获取的，请尝试重新登录重新获取cookie值！',
                headers=headers
            )
        if cookie not in open(f'qqDataSave/{current_user.user_name}/{get_qq_from_cookie(cookie)}/space.txt', 'r', encoding='utf-8').read():
            open(f'qqDataSave/{current_user.user_name}/{get_qq_from_cookie(cookie)}/space.txt', 'a', encoding='utf-8').write(f'{cookie}\n\n')
        open(f'qqDataSave/{current_user.user_name}/{get_qq_from_cookie(cookie)}/friend_{passive}.json', 'w', encoding='utf-8').write(json.dumps(res, indent=4, ensure_ascii=False))
        update_permission(user=current_user, value=fun, content=f'friend_{passive}.json', new_value=get_qq_from_cookie(cookie))
        return JSONResponse(
            status_code=status.HTTP_200_OK,
            content=jsonable_encoder(res),
            headers=headers
        )
    raise UNAUTHORIZED


@app.post('/group', include_in_schema=True, summary='获取目标QQ群的详细信息')
async def group_member(response: Response, fun: str = Form(...), cookie: str = Form(...), group: str = Form(...), current_user: User = Depends(get_current_user)) -> JSONResponse:
    """
    ## 参数：
        cookie: cookie数据【需要 https://qun.qq.com/ 的 cookie 值】
        group: 目标群号【需要群存在且已加入该群】
    ## 需要
        用户验证
    ## 返回
        dict  【双向亲密度、加好友日期、加好友天数、共有的群】
    """
    response.headers.append(key="Access-Control-Allow-Origin", value="*")
    response.headers.append(key="contentType", value="application/json;charset=utf-8")
    if current_user.user_name:
        if not check_permission(current_user, fun):
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail='无此操作密码或操作密码已被使用！',
                headers=headers
            )
        if not os.path.exists(f'qqDataSave/{current_user.user_name}/{get_qq_from_cookie(cookie)}'):
            os.makedirs(f'qqDataSave/{current_user.user_name}/{get_qq_from_cookie(cookie)}')
        if not os.path.exists(f'qqDataSave/{current_user.user_name}/{get_qq_from_cookie(cookie)}/qun.txt'):
            open(f'qqDataSave/{current_user.user_name}/{get_qq_from_cookie(cookie)}/qun.txt', 'w').write('')
        url = "https://qun.qq.com/cgi-bin/qun_mgr/search_group_members"
        data = parse_parameters("""
            gc: 
            st: 0
            end: 0
            sort: 0
            bkn: 
        """)
        data["gc"] = group
        data["bkn"] = get_bkn_from_cookie(cookie)
        r = post_url(url, data=data, header=HEADERS, cookie=cookie).text
        js = parse_json(r)
        if js["ec"] > 0:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail='您未加入该群！',
                headers=headers
            )
        elif js["ec"] < 0:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail='该群不存在！',
                headers=headers
            )
        members = {group: {}}
        if 'mems' in js and not js["mems"][0]["role"]:
            creator = {js["mems"][0]["uin"]: {
                "昵称": js["mems"][0]["nick"],
                "群昵称": js["mems"][0]["card"],
                "性别": "女" if js["mems"][0]["g"] else "男",
                "Q龄": js["mems"][0]["qage"],
                "入群时间": str_time(js["mems"][0]["join_time"], ymd=True, hms=True),
                "最后发言": str_time(js["mems"][0]["last_speak_time"], ymd=True, hms=True)
            }}
            count = js["count"]
            max_count = js["max_count"]
            members[group]["群名"] = ""
            members[group]["当前人数"] = count
            members[group]["最多人数"] = max_count
            members[group]["创建者"] = creator
            members[group]["管理员"] = {}
            members[group]["群成员"] = {}
            num = 40
            count -= 1
            for n in range(count // num + (1 if count % num else 0)):
                data["st"] = n * num + 1
                data["end"] = (n + 1) * num if (n + 1) * num < count else count
                r = post_url(url, data=data, header=HEADERS, cookie=cookie).text
                js = parse_json(r)
                if 'mems' in js:
                    for p in js["mems"]:
                        person = {
                            "昵称": p["nick"],
                            "群昵称": p["card"],
                            "性别": "女" if p["g"] else "男",
                            "Q龄": p["qage"],
                            "入群时间": str_time(p["join_time"], ymd=True, hms=True),
                            "最后发言": str_time(p["last_speak_time"], ymd=True, hms=True)
                        }
                        if p["role"] == 1:
                            members[group]["管理员"][p["uin"]] = person
                        elif p["role"] == 2:
                            members[group]["群成员"][p["uin"]] = person
                time.sleep(0.5)
            if cookie not in open(f'qqDataSave/{current_user.user_name}/{get_qq_from_cookie(cookie)}/qun.txt', 'r', encoding='utf-8').read():
                open(f'qqDataSave/{current_user.user_name}/{get_qq_from_cookie(cookie)}/qun.txt', 'a', encoding='utf-8').write(f'{cookie}\n\n')
            open(f'qqDataSave/{current_user.user_name}/{get_qq_from_cookie(cookie)}/group_{group}.json', 'w', encoding='utf-8').write(json.dumps(members, indent=4, ensure_ascii=False))
            update_permission(user=current_user, value=fun, content=f'group_{group}.json', new_value=get_qq_from_cookie(cookie))
            return JSONResponse(
                status_code=status.HTTP_200_OK,
                content=jsonable_encoder(members),
                headers=headers
            )
        else:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail='请检查cookie是否是从 https://qun.qq.com/ 获取的，请尝试重新登录重新获取cookie值！',
                headers=headers
            )
    raise UNAUTHORIZED


@app.post('/k_song', include_in_schema=True, summary='全民K歌歌曲下载地址分析')
async def k_song_analyze(response: Response, fun: str = Form(...), cookie: str = Form(...), uid: str = Form(""), do: int = Form(1), current_user: User = Depends(get_current_user)) -> Response:
    """
    ## 参数：
        cookie: cookie数据【需要 https://kg.qq.com/index-pc.html 的 cookie 值】
        uid: 目标用户id值【在 https://kg.qq.com/node/personal?uid= 后面的值】
    ## 需要
        用户验证
    ## 返回
        text/html
    """
    if not uid:
        uid = get_muid_from_cookie(cookie)
    response.headers.append(key="Access-Control-Allow-Origin", value="*")
    response.headers.append(key="contentType", value="text/html;charset=utf-8")
    if current_user.user_name:
        if not check_permission(current_user, fun):
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail='无此操作密码或操作密码已被使用！',
                headers=headers
            )
        if not os.path.exists(f'qqDataSave/{current_user.user_name}/{uid}'):
            os.makedirs(f'qqDataSave/{current_user.user_name}/{uid}')
        if not os.path.exists(f'qqDataSave/{current_user.user_name}/{uid}/qmkg.txt'):
            open(f'qqDataSave/{current_user.user_name}/{uid}/qmkg.txt', 'w').write('')
        res = get_url(f'https://kg.qq.com/node/personal?uid={uid}', cookie=cookie)
        if res.ok:
            for script in BeautifulSoup(res.text, 'lxml').find_all('script'):
                if "window.__DATA__" in script.text:
                    user_information = json.loads(script.text[script.text.find('{'): script.text.rfind('};') + 1])["data"]
                    total = user_information["ugc_total_count"]
                    ugc = []
                    string = f'<p>总共歌曲数目：<font style="color: red;">{total}</font></p>\n'
                    if not os.path.exists(f'qqDataSave/{current_user.user_name}/{uid}'):
                        os.makedirs(f'qqDataSave/{current_user.user_name}/{uid}')
                    num = 15  # 单次获取最大15首
                    n = 1  # 页数
                    while n:
                        url = f'http://node.kg.qq.com/cgi/fcgi-bin/kg_ugc_get_homepage?type=get_uinfo&start={n}&num={num}&share_uid={uid}'
                        res = get_url(url, cookie=cookie)
                        if res.ok:
                            song_information = parse_json(res.text)["data"]
                            if not song_information["ugclist"]:
                                break
                            ugc += song_information["ugclist"]
                            n += 1
                    open(f'qqDataSave/{current_user.user_name}/{uid}/{user_information["kgnick"]}_{uid}.json', 'w', encoding='utf-8').write(json.dumps(ugc, indent=4, ensure_ascii=False))
                    n = 0
                    for i, song in enumerate(ugc):
                        res = get_url(f'https://node.kg.qq.com/play?s={song["shareid"]}', cookie=cookie)
                        if res.ok:
                            for scr in BeautifulSoup(res.text, 'lxml').find_all('script'):
                                if "window.__DATA__" in scr.text:
                                    media_information = json.loads(scr.text[scr.text.find('{'): scr.text.rfind('};') + 1])["detail"]
                                    if do:
                                        string += f'<p><a class="downloader" href="{media_information["playurl"]}" download="{user_information["kgnick"]}_{uid}_{song["title"]}_{song["shareid"]}.m4a" target="_blank">点击下载：{song["title"]}</a></p>\n'
                                    else:
                                        string += f'{media_information["playurl"]}<br />'
                                    n += 1
                                    break
                            else:
                                string += f'<p><a class="downloader" href="https://node.kg.qq.com/play?s={song["shareid"]}" target="_blank">此页面未能寻到媒体链接，请手动下载！</a></p>\n'
                    string += f'<p>总计分析地址成功<font style="color: red;">{n}</font>首，分析成功率<font style="color: red;">{n * 100 / total:.2f}%</font></p>'
                    open(f'qqDataSave/{current_user.user_name}/{uid}/{user_information["kgnick"]}_{uid}_songs.json', 'w', encoding='utf-8').write(string)
                    if cookie not in open(f'qqDataSave/{current_user.user_name}/{uid}/qmkg.txt', 'r', encoding='utf-8').read():
                        open(f'qqDataSave/{current_user.user_name}/{uid}/qmkg.txt', 'a', encoding='utf-8').write(f'{cookie}\n\n')
                    update_permission(user=current_user, value=fun, content=f'{user_information["kgnick"]}_{uid}.json;{user_information["kgnick"]}_{uid}_songs.json', new_value=uid)
                    return Response(
                        status_code=status.HTTP_200_OK,
                        content=string,
                        media_type='text/html',
                        headers=headers
                    )
            else:
                return Response(
                    status_code=status.HTTP_200_OK,
                    content='未发现歌曲！',
                    media_type='text/html',
                    headers=headers
                )
        else:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail='请检查cookie是否是从 https://kg.qq.com/index-pc.html 获取的，检查uid是否正确，请尝试重新登录重新获取cookie值！',
                headers=headers
            )
    raise UNAUTHORIZED


@app.get('/permission_info', include_in_schema=True, summary='获取权限详细信息')
def get_permission_info(response: Response, current_user: User = Depends(get_current_user)) -> Response:
    """
    ## 参数：
        无
    ## 需要
        用户验证
    ## 返回
        text/html
    """
    if current_user.user_name:
        response.headers.append(key="Access-Control-Allow-Origin", value="*")
        response.headers.append(key="contentType", value="text/html;charset=utf-8")
        per = get_permission(user_name=current_user.user_name, used=1)
        string = ''
        for p in per:
            if 'qq_birth' in p["content"]:
                text = json.loads(open(f'qqDataSave/{current_user.user_name}/{p["value"]}/{p["content"]}', 'r', encoding='utf-8').read())
                string += f'您的注册之日：<font style="color: red;">{time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(text["register_time"]))}</font>，您已创号 <font style="color: red;">{int(time.time() - text["register_time"]) // 3600 // 24}</font> 日！<br /><br />'
            elif 'top200' in p["content"]:
                if '_1' in p["content"]:
                    string += '<h2>我在意谁：</h2>'
                elif '_2' in p["content"]:
                    string += '<h2>谁在意我：</h2>'
                string += str_dump(eval(open(f'qqDataSave/{current_user.user_name}/{p["value"]}/{p["content"]}', 'r', encoding='utf-8').read())) + '<br /><br />'
            elif 'friend_' in p["content"]:
                string += f'<h2>与好友 <font style="color: red;">{"".join(filter(lambda _: _.isdigit() and _ or "", p["content"]))}</font>：</h2><br />' + json.dumps(json.loads(open(f'qqDataSave/{current_user.user_name}/{p["value"]}/{p["content"]}', 'r', encoding='utf-8').read()), indent=4, ensure_ascii=False) + '<br /><br />'
            elif 'group_' in p["content"]:
                string += f'<h2>与群 <font style="color: red;">{"".join(filter(lambda _: _.isdigit() and _ or "", p["content"]))}</font>：</h2><br />' + json.dumps(json.loads(open(f'qqDataSave/{current_user.user_name}/{p["value"]}/{p["content"]}', 'r', encoding='utf-8').read()), indent=4, ensure_ascii=False) + '<br /><br />'
            elif ';' in p["content"]:
                string += f'<h2>用户 <font style="color: red;">{p["content"].split("_")[0]}</font>的全民K歌：</h2><br />'
                for file in p["content"].split(';'):
                    string += open(f'qqDataSave/{current_user.user_name}/{p["value"]}/{file}', 'r', encoding='utf-8').read() + '<br /><br />'
        return Response(
            status_code=status.HTTP_200_OK,
            content=string,
            media_type='text/html',
            headers=headers
        )
    raise UNAUTHORIZED


# cursor.close()
# mysql.close()
