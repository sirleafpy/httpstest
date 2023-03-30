# -*- coding: utf-8 -*-
import os
import subprocess


def subprocess_run(command):
    print(f"Execute a command > {command}")
    ret = subprocess.run(command, shell=True,
                         stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                         encoding="utf-8")
    status, stdout, stderr = ret.returncode, ret.stdout, ret.stderr
    if status == 0:
        print(f'Execute success < {stdout}')
    else:
        print(f'Execute failure < {stderr}')


def generate_certs_info():
    baidu_base64_command = '''openssl s_client -connect www.baidu.com:443 -servername www.baidu.com | openssl x509 -pubkey -noout | openssl rsa -pubin -outform der | openssl dgst -sha256 -binary | openssl enc -base64'''
    subprocess_run(baidu_base64_command)

    bing_pem_command = '''openssl s_client -connect bing.com:443 -servername bing.com | openssl x509 -out bing.pem'''
    subprocess_run(bing_pem_command)

    so_pem_command = '''openssl s_client -connect so.com:443 -servername so.com | openssl x509 -out so.pem'''
    subprocess_run(so_pem_command)

    sogou_pem_command = '''openssl s_client -connect sogou.com:443 -servername sogou.com | openssl x509 -out sogou.pem'''
    subprocess_run(sogou_pem_command)

    zhihu_base64_command = '''openssl s_client -connect zhihu.com:443 -servername zhihu.com | openssl x509 -pubkey -noout | openssl rsa -pubin -outform der | openssl dgst -sha256 -binary | openssl enc -base64'''
    subprocess_run(zhihu_base64_command)


def generate_server_cert():
    cmd_01 = '''openssl genrsa -out server-key.key 2048'''
    print(cmd_01)
    os.system(cmd_01)

    cmd_02 = '''openssl req -new -out server-req.csr -key server-key.key'''
    print(cmd_02)
    os.system(cmd_02)

    cmd_03 = '''openssl x509 -req -in server-req.csr -out server-cert.cer -signkey server-key.key  -CAcreateserial -days 3650'''
    print(cmd_03)
    os.system(cmd_03)


def generate_client_cert():
    cmd_01 = '''openssl genrsa -out client-key.key 2048'''
    print(cmd_01)
    os.system(cmd_01)

    cmd_02 = '''openssl req -new -out client-req.csr -key client-key.key'''
    print(cmd_02)
    os.system(cmd_02)

    cmd_03 = '''openssl x509 -req -in client-req.csr -out client-cert.cer -signkey client-key.key -CAcreateserial -days 3650'''
    print(cmd_03)
    os.system(cmd_03)

    input("Press any key to continue:")

    cmd_04 = '''openssl pkcs12 -export -clcerts -in client-cert.cer -inkey client-key.key -out client.p12'''
    print(cmd_04)
    os.system(cmd_04)


if __name__ == '__main__':
    generate_certs_info()

    # generate_server_cert()

    # generate_client_cert()
