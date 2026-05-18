from flask import Flask, request
import subprocess
import os
import hashlib
import yaml
import requests

app = Flask(__name__)

password = "demo_password_123"
secret = "demo_secret_123"

@app.route("/test")
def test():
    cmd = request.args.get("cmd")
    filename = request.args.get("file")
    url = request.args.get("url")

    subprocess.run(cmd, shell=True)
    os.system("whoami")
    os.popen("id")

    eval("1 + 1")
    exec("print('test')")

    hashlib.md5(b"demo").hexdigest()
    hashlib.sha1(b"demo").hexdigest()

    yaml.load("name: test")

    open(filename).read()
    requests.get(url)

    return "done"

app.run(debug=True)
