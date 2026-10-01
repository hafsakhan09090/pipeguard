"""INTENTIONALLY INSECURE demo code used only to test PipeGuard. Do not copy."""
import hashlib
import os
import pickle
import sqlite3
import subprocess

import requests
import yaml
from flask import Flask, request

app = Flask(__name__)
DB_PASSWORD = "Zk3$9fQ!x7Lm2Pq8Rt5Vw1"


def get_user(conn, name):
    cur = conn.cursor()
    cur.execute(f"SELECT * FROM users WHERE name = '{name}'")
    return cur.fetchall()


@app.route("/run")
def run():
    os.system("ping " + request.args["host"])
    subprocess.run(request.args["cmd"], shell=True)
    return eval(request.args["expr"])


@app.route("/load", methods=["POST"])
def load():
    obj = pickle.loads(request.data)
    cfg = yaml.load(request.data)
    return str(hashlib.md5(request.data).hexdigest()) + str(obj) + str(cfg)


def fetch(url):
    return requests.get(url, verify=False)


if __name__ == "__main__":
    app.run(debug=True)
