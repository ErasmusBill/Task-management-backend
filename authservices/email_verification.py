import requests
import os


def verify_email(email):
    api_key = "e505e934619f45248f8aa9a440cb6e9a"
    url = f"https://api.zerobounce.net/v2/validate?api_key={api_key}&email={email}"
    
    try:
        response = requests.get(url, timeout=10)
        data = response.json()
        
        if response.status_code == 200:
            status = data.get("status")
            return {"valid":status in ("valid","catch-all"), "data":data}
        return {"valide":False,"error":"API request failed"}
    except Exception as e:
        return {"valid":False,"error":str(e)}