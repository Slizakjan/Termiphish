import requests
import time
import random
import base64
import string
import uuid
import json

import requests.cookies

INSTAGRAM_URL = 'https://www.instagram.com'
LOGIN_URL = 'https://www.instagram.com/api/v1/web/accounts/login/ajax/'
TWOFA_REFER_URL = 'https://www.instagram.com/accounts/login/two_factor'
TWOFA_URL = "https://www.instagram.com/api/v1/web/accounts/login/ajax/two_factor/"
SMS_URL = 'https://www.instagram.com/api/v1/web/accounts/send_two_factor_login_sms/'

# Funkce pro načtení stránky, kliknutí na tlačítko a získání cookies
def get_cookies_with_click(url=None):
    def generate_datr():
        """Vygeneruje náhodnou datr cookie."""
        random_bytes = random.randbytes(16) if hasattr(random, "randbytes") else bytes(random.getrandbits(8) for _ in range(16))
        encoded = base64.b64encode(random_bytes).decode("utf-8").rstrip("=")
        timestamp = hex(int(time.time()))[2:].upper()
        return f"{encoded}{timestamp}"

    def generate_mid():
        """Vygeneruje náhodnou mid cookie."""
        chars = string.ascii_letters + string.digits
        return ''.join(random.choices(chars, k=26))

    def get_csrftoken():
        """Získá CSRF token z úvodní stránky Instagramu."""
        response = requests.get(INSTAGRAM_URL)
        csrftoken = response.cookies.get("csrftoken")
        if not csrftoken:
            csrftoken = response.cookies.get_dict().get("csrftoken")
            if not csrftoken:
                raise ValueError("Nepodařilo se získat CSRF token.")
        return csrftoken

    csrftoken = get_csrftoken()
        
    cookies = {
        "csrftoken": csrftoken,
        "_js_ig_did": str(uuid.uuid4()).upper(),
        "_js_datr": generate_datr(),
        "_js_mid": generate_mid()
    }

    variables = {"ig_did": None}
    variables["ig_did"] = cookies["_js_ig_did"]
    data = {"variables": json.dumps(variables)}

    # Pokus o validaci cookies GET requestem na hlavní stránku
    response = requests.post(INSTAGRAM_URL, cookies=cookies, data=data)

    if response.status_code == 200:
        cookies.update(response.cookies.get_dict())
        cookies.pop("_js_ig_did", None)
        cookies.pop("_js_datr", None)
        cookies.pop("_js_mid", None)
        return cookies
    else:
        raise ValueError("Instagram odmítl cookies.")

def filter_tokens(data):
    tokens = {
        "csrftoken": None,
        "datr": None,
        "mid": None,
        "ig_did": None
    }

    # Kontrola, zda data jsou slovník, nebo seznam cookies
    if isinstance(data, dict):
        # Pokud data jsou slovník, získej hodnoty přímo
        for key in tokens.keys():
            if key in data:
                tokens[key] = data[key]
    elif isinstance(data, list):
        # Pokud data jsou seznam cookies, projdi ho
        for cookie in data:
            if isinstance(cookie, dict) and 'name' in cookie and 'value' in cookie:
                if cookie['name'] == 'csrftoken':
                    tokens['csrftoken'] = cookie['value']
                elif cookie['name'] == 'datr':
                    tokens['datr'] = cookie['value']
                elif cookie['name'] == 'mid':
                    tokens['mid'] = cookie['value']
                elif cookie['name'] == 'ig_did':
                    tokens['ig_did'] = cookie['value']
            else:
                print(f"Varování: Neočekávaný formát cookie: {cookie}")

    return tokens

def craft_headers(url, user_agent, tokens=None, lang="en-EN"):
    if tokens == None:
        tokens = filter_tokens(get_cookies_with_click('https://www.instagram.com'))
    # Hlavičky požadavku
    headers = {
        "X-Csrftoken": tokens['csrftoken'],
        "X-Web-Device-Id": tokens['ig_did'],
        "X-Instagram-Ajax": "1017706361",  # Tato hodnota může být změněna dle požadavku serveru
        "X-Requested-With": "XMLHttpRequest",
        "User-Agent": user_agent if user_agent else "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36", # Mozilla/5.0 (Windows NT 10.0; Win64; x64)
        "Content-Type": "application/x-www-form-urlencoded",
        "Referer": url, #"https://www.instagram.com/accounts/login/two_factor"
        "Accept-Language": lang
    }
    return headers, tokens

def craft_twofa_data(method, code, data):
    username = data.get("username")
    identifier = data.get("two_factor_identifier")
    twofa_data = {
        'username': username,
        "verificationCode": code,
        "identifier": identifier,
        'verification_method': method,  # TOTP 1 for sms 2 for backup codes 3 for totp
        'trust_signal': "true",
        'queryParams': '{"next":"/"}'  # Pokud to je potřeba, přidej další parametry
    }
    return twofa_data

def craft_login_data(username, password):
    # Login data
    login_data = {
        "username": username,
        "enc_password": f'#PWD_INSTAGRAM_BROWSER:0:&:{password}',
        "optIntoOneTap": "false",
        "queryParams": "{}",
        "trustedDeviceRecords": "{}",
    }
    return login_data

def login(username, password, user_agent=None, tokens=None):
    headers, tokens = craft_headers(LOGIN_URL, user_agent, tokens)
    #print(tokens)
    
    login_data = craft_login_data(username, password)

    #response = session.post(LOGIN_URL, data=login_data, allow_redirects=True)
    response = requests.post(LOGIN_URL, headers=headers, cookies=tokens, data=login_data)

    try:
        if response.status_code == 200 and response.json().get('authenticated'):
            sessionid = response.cookies.get('sessionid')
            return [response.json(), sessionid, None], tokens
        elif response.status_code == 400 and response.json().get('two_factor_required'):
            identifier = response.json().get('two_factor_info').get('two_factor_identifier')
            return [response.json(), None, identifier], tokens
        else:
            return [response.json(), None, None], tokens
    except Exception as e:
        print(e)
        json_template = [
            {
                'message': 'checkpoint_required',
                'status': 'fail'
            },
            None
        ]
        return json_template

def send_sms(username, identifier, user_agent, tokens, lang=None):
    refer_url = "https://www.instagram.com/accounts/login/two_factor"

    if lang != None:
        headers, tokens = craft_headers(refer_url, user_agent, tokens, lang)
    else:
        headers, tokens = craft_headers(refer_url, user_agent, tokens)

    sms_data = {
        'username': username,
        "identifier": identifier,
    }
    response = requests.post(SMS_URL, data=sms_data, headers=headers, cookies=tokens)
    return response

def twofa(username, tokens, identifier, method, code, user_agent=None):
    headers = craft_headers(TWOFA_REFER_URL, user_agent, tokens)

    user_data = {'username': username, 'two_factor_identifier': identifier}

    data = craft_twofa_data(method, code, user_data)

    #print(TWOFA_URL, headers[0], tokens, data)
    #print("#################################################")

    response = requests.post(TWOFA_URL, headers=headers[0], cookies=tokens, data=data)
    return response

# Volání funkce s URL Instagramu
#cookies = get_cookies_with_click('https://www.instagram.com')
#print(cookies)
