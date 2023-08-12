import functools
import re
import subprocess
import sys
import time
from concurrent.futures import ThreadPoolExecutor
import chardet
import paramiko
import os

import retrying
import yaml

# ==============================================================================================

version = "1.23.1"
install_dir = "/opt/nginx"
global_password = None
global_key_filename = "~/.ssh/id_rsa"
args = f"--prefix={install_dir} --with-stream --with-compat --with-debug \
    --with-pcre-jit --with-http_ssl_module --with-http_stub_status_module \
    --with-http_realip_module --with-http_auth_request_module \
    --with-http_v2_module --with-http_dav_module --with-http_slice_module \
    --with-threads --with-http_addition_module --with-http_gunzip_module \
    --with-http_gzip_static_module --with-http_sub_module"


# 安装依赖库
def install_nginx_devel(server: dict) -> list:
    sshclient: paramiko.SSHClient = server['sshclient']

    # 定义Debian系统依赖安装函数
    def ubuntu_devel() -> int:
        sshclient.exec_command("sudo apt update")
        in_stdin, in_stdout, in_stderr = sshclient.exec_command("sudo apt-get install \
                                                               -y gcc make libssl-dev libpcre3-dev zlib1g-dev")
        if in_stdout.channel.recv_exit_status() != 0:
            return 1
        else:
            return 0

    # 定义Redhat系 系统依赖安装函数
    def redhat_devel() -> int:
        sshclient.exec_command("sudo yum makecache")
        in_stdin, in_stdout, in_stderr = sshclient.exec_command("sudo \
                                                                yum install -y gcc make openssl-devel pcre-devel zlib-devel")
        if in_stdout.channel.recv_exit_status() != 0:
            return 1
        else:
            return 0

    # 检查系统类型
    stdin, stdout, stderr = sshclient.exec_command("uname -a")
    os_info = stdout.read().decode()
    if ("Ubuntu" in os_info) or ("Debian" in os_info):
        is_done = False
        for i in range(3):
            if ubuntu_devel() == 0:
                is_done = True
                break
        return [0, "is done"] if is_done is True else [1, "is not done"]
    else:
        is_done = False
        for i in range(3):
            if redhat_devel() == 0:
                is_done = True
                break
        return [0, "is done"] if is_done is True else [1, "is not done"]


# 下载源码
def download_source_file() -> list:
    global version

    # 查找文件
    if os.path.exists(f"nginx-{version}.tar.gz"):
        return [0, "文件存在"]

    # 无文件则下载
    result = subprocess.run(['wget', f'https://nginx.org/download/nginx-{version}.tar.gz'], stdout=subprocess.PIPE)
    if result.returncode == 0:
        return [0, "文件下载成功"]
    else:
        return [1, "文件下载失败"]


# 上传源代码
def put_nginx_source_file(server: dict) -> list:
    global version
    global install_dir

    # 源代码检查
    if not os.path.exists(f"nginx-{version}.tar.gz"):
        return [1, "源代码文件未找到"]

    # 上传准备
    sshclient: paramiko.SSHClient = server['sshclient']
    sftp = sshclient.open_sftp()

    # 上传源代码
    sftp.put(f"nginx-{version}.tar.gz", f"/tmp/nginx-{version}.tar.gz")
    try:
        sftp.stat(f"/tmp/nginx-{version}.tar.gz")
    except Exception as e:
        print(e)
        sftp.close()
        return [2, "文件上传失败"]
    sftp.close()

    # 解压文件
    stdin, stdout, stderr = sshclient.exec_command(f"tar xf /tmp/nginx-{version}.tar.gz -C /tmp")
    return [0, "上传完成"] if stdout.channel.recv_exit_status() == 0 else [3, stderr.read().decode()]


# 编译安装nginx
def build_nginx(server: dict) -> list:
    global version
    global install_dir
    global args

    # 配置args
    en_args = server['args'] if 'args' in server else args

    # 安装脚本
    build_context = f"""#!/bin/bash
cd /tmp/nginx-{version}
./configure {en_args}
make && sudo make install
"""

    # 写入安装脚本
    sshclient: paramiko.SSHClient = server['sshclient']
    sftp = sshclient.open_sftp()

    with sftp.open("/tmp/build_nginx.sh", "w") as f:
        f.write(build_context)
    time.sleep(1)
    sftp.close()

    # 运行安装脚本
    stdin, stdout, stderr = sshclient.exec_command("bash /tmp/build_nginx.sh")
    return [0, stdout.read().decode()] if stdout.channel.recv_exit_status() == 0 else [1, stderr.read().decode()]


# 上传配置文件
def put_nginx_conf(server: dict) -> list:
    nginx_conf = server['nginx_conf'] if 'nginx_conf' in server else None
    global version
    global install_dir

    # 是否要上传
    if nginx_conf is None:
        return [0, "末指定配置文件，不需要上传"]

    # 读取配置文件
    if not os.path.exists(nginx_conf):
        return [1, "文件不存在"]
    with open(nginx_conf, "r") as f:
        nginx_conf_context = f.read()

    # 写入配置文件
    sshclient: paramiko.SSHClient = server['sshclient']
    sftp = sshclient.open_sftp()

    with sftp.open(f"/tmp/nginx.conf", "w") as f:
        f.write(nginx_conf_context)

    time.sleep(1)
    sftp.close()

    # 移动文件
    stdin, stdout, stderr = sshclient.exec_command(f"sudo mv /tmp/nginx.conf {install_dir}/conf/nginx.conf")
    if stdout.channel.recv_exit_status() != 0:
        return [1, f"{server['host']} 上传配置文件失败"]

    return [0, "结束"]


# 上传网站文件
def put_web_tar(server: dict) -> list:
    global install_dir

    if not ('web_tar' in server):
        return [0, {"err_info": "没有配置web压缩包!"}]
    # 上传文件
    if not os.path.exists(server['web_tar']):
        return [1, {"err_info": "web压缩文件不存在"}]

    #
    print(f"{server['host']}上传网站文件")
    sshclient: paramiko.SSHClient = server['sshclient']
    sftp = sshclient.open_sftp()
    sftp.put(server['web_tar'], "/tmp/web.tar")
    try:
        sftp.stat("/tmp/web.tar")
    except:
        return [1, "上传文件失败"]

    sftp.close()
    # 解压文件
    stdin, stdout, stderr = sshclient.exec_command(f"sudo tar xf /tmp/web.tar -C {install_dir}/html")
    if stdout.channel.recv_exit_status() != 0:
        return [2, {"err_info": f"{server['host']}解压网站文件失败"}]
    sshclient.exec_command("sudo rm /tmp/web.tar")
    return [0, {"info": "完成"}]


# 写入service文件
def write_nginx_service_file(server: dict) -> list:
    global install_dir
    server_context = f"""[Unit]
Description=nginx.service
[Service]
Type=forking
ExecStart={install_dir}/sbin/nginx -c {install_dir}/conf/nginx.conf
ExecReload={install_dir}/sbin/nginx -s reload
ExecStop={install_dir}/sbin/nginx -s stop
Restart=on-failure
PrivateTmp=yes
Delegate=yes
[Install]
WantedBy=multi-user.target   
"""

    # 写入文件
    sshclient: paramiko.SSHClient = server['sshclient']
    sftp = sshclient.open_sftp()
    with sftp.open('/tmp/nginx.service', "w") as f:
        f.write(server_context)
    sftp.close()
    # 移动文件
    stdin, stdout, stderr = sshclient.exec_command(f"sudo mv /tmp/nginx.service /usr/lib/systemd/system/nginx.service")
    if stdout.channel.recv_exit_status() != 0:
        return [1, f"{server['host']}写入service文件失败"]

    return [0, 'None']


# 安装 nginx
def test(result: list) -> bool:
    return False if result[0] == 0 else True


def install_nginx(server: dict) -> list:
    global install_dir
    # 安装依赖
    print(f"{server['host']}安装依赖")
    result = install_nginx_devel(server)
    if result[0] != 0:
        return result

    # 上传源代码
    print(f"{server['host']}上传源码")
    result = put_nginx_source_file(server)
    if result[0] != 0:
        return result

    # 清理老文件
    # 危险操作，只清理默认文件
    server['sshclient'].exec_command(f"sudo rm -rf /opt/nginx")

    # 编译安装
    print(f"{server['host']}安装nginx")
    result = build_nginx(server)
    if result[0] != 0:
        return result

    # 写入配置文件
    print(f"{server['host']}写入配置文件")
    result = put_nginx_conf(server)
    if result[0] != 0:
        return result

    # 写入service文件
    print(f"{server['host']}写入service文件")
    result = write_nginx_service_file(server)
    if result[0] != 0:
        return result

    # 上传web文件
    result = put_web_tar(server)
    if result[0] != 0:
        print(result)

    # 启动nginx
    print(f"{server['host']}启动nginx")
    stdin, stdout, stderr = server['sshclient'].exec_command("sudo systemctl is-active nginx")
    if stdout.channel.recv_exit_status() != 0:
        # 启动nginx
        server['sshclient'].exec_command("sudo systemctl daemon-reload")
        stdin, stdout, stderr = server['sshclient'].exec_command("sudo systemctl enable --now nginx")
    else:
        # 重启nginx
        server['sshclient'].exec_command("sudo systemctl daemon-reload")
        stdin, stdout, stderr = server['sshclient'].exec_command("sudo systemctl restart nginx")

    if stdout.channel.recv_exit_status() != 0:
        return [1, f"{server['host']}启动nginx失败"]
    else:
        return [0, "启动成功"]


# =================================================================================
"""公共函数区"""


def connect_server(server: dict) -> list:
    global global_password
    global global_key_filename
    # 参数配置
    if not ('host' in server):
        return [1, f"{server}必须含有host属性"]

    host = server['host']
    port = server['port'] if 'port' in server else 22
    username = server['username'] if 'username' in server else os.getlogin()
    password = server['password'] if 'password' in server else global_password
    key_filename = server['key_filename'] if 'key_filename' in server else global_key_filename

    if re.match("~/.*", key_filename):
        home_dir = os.path.expanduser("~")
        key_filename = key_filename.replace('~', home_dir)

    # 登录
    sshclient = paramiko.SSHClient()
    sshclient.set_missing_host_key_policy(paramiko.AutoAddPolicy)

    try:
        if password is None:
            sshclient.connect(hostname=host, port=port, username=username, key_filename=key_filename)
        else:
            sshclient.connect(hostname=host, port=port, username=username, password=password)
        server['sshclient'] = sshclient
        re_num = 0
    except Exception as e:
        re_num = 1
        server['sshclient'] = None

    return [re_num, server]


def connect_servers(server_list: list) -> list:
    new_list = []
    err_login_list = []
    if not server_list:
        return [1, {"err_info": "server_list 为空"}]
    for server in server_list:
        result = connect_server(server)
        if result[0] != 0:
            err_login_list.append(result[1])
            continue
        new_list.append(result[1])

    return [0, new_list, err_login_list]


# ==================================================================================

def servers_install_nginx(file: str) -> list:
    global version
    global install_dir
    global global_password
    global global_key_filename

    # 检查配置文件
    if not os.path.exists(file):
        err = {
            "err_info": "没有找到配置文件"
        }
        print(err)
        return [1, err]

    # 读取配置文件
    with open(file, "rb") as f:
        charset = chardet.detect(f.read(4))['encoding']
    with open(file, "r", encoding=charset) as f:
        nginx_conf = yaml.safe_load(f)

    # 配置全局变量
    version = nginx_conf['version'] if 'version' in nginx_conf else version
    install_dir = nginx_conf['install_dir'] if 'install_dir' in nginx_conf else install_dir
    global_password = nginx_conf['global_password'] if 'global_password' in nginx_conf else global_password
    global_key_filename = nginx_conf[
        'global_key_filename'] if 'global_key_filename' in nginx_conf else global_key_filename

    # 下载源码
    download_source_file()
    # 登录 servers
    result = connect_servers(nginx_conf['servers'])
    if result[0] != 0:
        print(f"servers 列表为空")
    elif len(result[1]) != len(nginx_conf['servers']):
        for server in result[2]:
            print(f"{server['host']}登录 失败")
        return [1, "登录 问题"]

    # 安装
    login_servers = result[1]
    threads = []
    with ThreadPoolExecutor(max_workers=5) as run_t:
        for server in login_servers:
            install_nginx_args_server = functools.partial(install_nginx, server)
            t = run_t.submit(install_nginx_args_server)
            threads.append(t)

    # 等待线程结束
    while True:
        all_done = True
        for t in threads:
            if not t.done():
                all_done = False
        if all_done is True:
            break
        time.sleep(1)

    # 输出 结果
    re_num = 0
    for t in threads:
        if t.result()[0] != 0:
            print(t.result())
            re_num = 1

    return [re_num, "None"]


def print_help():
    help_context = f"""
Usage: {sys.argv[0]} [help|print_config|print_nginx_conf] 
"""
    print(help_context)


def print_config():
    config_context = """version: "1.23.1" #nginx版本
# 配置完成后请把所有注释删除
install_dir: "/opt/nginx" # 安装路径，默认为/opt/nginx
global_password: None # 默认密码,如果 不为None则会忽略密钥使用密码
global_key_filename: "~/.ssh/id_rsa" # 默认密钥
servers:
  - host: 192.168.1.31
    username: "vga" # 用户名,不填则使用登录名
    password: "123456" # 密码,注释则使用全局密码
    key_filename: "~/.ssh/id_rsa" # 密钥文件，注释则使用全局密钥
    nginx_conf: nginx.conf # 配置文件
    cert: "pub.pem" # nginx公钥当前版本请自己上传，未实现配置
    key: "key.pem" # 私钥 , 当前 版本请自己上传， 末实现配置
  - host: 192.168.1.32
    username: "vga"
    password: "123456"
    key_filename: "~/.ssh/id_rsa"
    nginx_conf: nginx.conf
  - host: 192.168.1.33
    username: "vga"
    password: "123456"
    key_filename: "~/.ssh/id_rsa"
    nginx_conf: nginx.conf
"""
    print(config_context)


def print_nginx_conf():
    nginx_conf_context = """
#user  nobody;
worker_processes  1;

#error_log  logs/error.log;
#error_log  logs/error.log  notice;
#error_log  logs/error.log  info;

#pid        logs/nginx.pid;


events {
    worker_connections  1024;
}


http {
    include       mime.types;
    default_type  application/octet-stream;

    #log_format  main  '$remote_addr - $remote_user [$time_local] "$request" '
    #                  '$status $body_bytes_sent "$http_referer" '
    #                  '"$http_user_agent" "$http_x_forwarded_for"';

    #access_log  logs/access.log  main;

    sendfile        on;
    #tcp_nopush     on;

    #keepalive_timeout  0;
    keepalive_timeout  65;

    #gzip  on;

    server {
        listen       80;
        server_name  localhost;

        #charset koi8-r;

        #access_log  logs/host.access.log  main;

        location / {
            root   html;
            index  index.html index.htm;
        }

        #error_page  404              /404.html;

        # redirect server error pages to the static page /50x.html
        #
        error_page   500 502 503 504  /50x.html;
        location = /50x.html {
            root   html;
        }

        # proxy the PHP scripts to Apache listening on 127.0.0.1:80
        #
        #location ~ \.php$ {
        #    proxy_pass   http://127.0.0.1;
        #}

        # pass the PHP scripts to FastCGI server listening on 127.0.0.1:9000
        #
        #location ~ \.php$ {
        #    root           html;
        #    fastcgi_pass   127.0.0.1:9000;
        #    fastcgi_index  index.php;
        #    fastcgi_param  SCRIPT_FILENAME  /scripts$fastcgi_script_name;
        #    include        fastcgi_params;
        #}

        # deny access to .htaccess files, if Apache's document root
        # concurs with nginx's one
        #
        #location ~ /\.ht {
        #    deny  all;
        #}
    }


    # another virtual host using mix of IP-, name-, and port-based configuration
    #
    #server {
    #    listen       8000;
    #    listen       somename:8080;
    #    server_name  somename  alias  another.alias;

    #    location / {
    #        root   html;
    #        index  index.html index.htm;
    #    }
    #}


    # HTTPS server
    #
    #server {
    #    listen       443 ssl;
    #    server_name  localhost;

    #    ssl_certificate      cert.pem;
    #    ssl_certificate_key  cert.key;

    #    ssl_session_cache    shared:SSL:1m;
    #    ssl_session_timeout  5m;

    #    ssl_ciphers  HIGH:!aNULL:!MD5;
    #    ssl_prefer_server_ciphers  on;

    #    location / {
    #        root   html;
    #        index  index.html index.htm;
    #    }
    #}

}
"""
    print(nginx_conf_context)


# ==================================================================================
if __name__ == '__main__':
    if len(sys.argv) == 1:
        result = servers_install_nginx("nginx.yaml")
        sys.exit(result[0])
    elif sys.argv[1] == "help":
        print_help()
        sys.exit(0)
    elif sys.argv[1] == "print_config":
        print_config()
        sys.exit(0)
    elif sys.argv[1] == "print_nginx_conf":
        print_nginx_conf()
        sys.exit(0)
