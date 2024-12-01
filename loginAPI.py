from selenium.webdriver.common.by import By
from selenium import webdriver
import requests
import time

import requests.cookies

INSTAGRAM_URL = 'https://www.instagram.com'
LOGIN_URL = 'https://www.instagram.com/accounts/login/ajax/'
TWOFA_REFER_URL = 'https://www.instagram.com/accounts/login/two_factor'
TWOFA_URL = "https://www.instagram.com/api/v1/web/accounts/login/ajax/two_factor/"
SMS_URL = 'https://www.instagram.com/api/v1/web/accounts/send_two_factor_login_sms/'

# Funkce pro načtení stránky, kliknutí na tlačítko a získání cookies
def get_cookies_with_click(url):
    if url == None:
        url = INSTAGRAM_URL
    # Nastavení Chrome v headless režimu
    options = webdriver.ChromeOptions()
    options.add_argument("--no-sandbox")
    options.add_argument("--disable-dev-shm-usage")
    options.add_argument("--headless=new")  # Spustí bez grafického rozhraní

    # Vytvoří instanci prohlížeče Chrome
    driver = webdriver.Chrome(options=options)

    # Načte stránku
    driver.get(url)

    # Počkej, až se stránka plně načte
    time.sleep(3)

    # Kliknutí na tlačítko s třídami (pokud je potřeba)
    try:
        driver.find_element(By.CSS_SELECTOR, "._a9--._ap36._a9_0").click()
        time.sleep(1)  # Počkej na reakci po kliknutí
    except Exception as e:
        print("Tlačítko nebylo nalezeno nebo nešlo kliknout:", e)

    # Pokusy o získání cookies
    for attempt in range(10):
        # Získá cookies
        cookies = driver.get_cookies()
        
        # Vyhledání požadovaných cookies
        cookies_dict = {cookie['name']: cookie['value'] for cookie in cookies}
        datr = cookies_dict.get('datr')
        ig_did = cookies_dict.get('ig_did')
        mid = cookies_dict.get('mid')

        # Kontrola, jestli všechny požadované cookies existují
        if datr and ig_did and mid:
            #print("Všechny požadované cookies byly získány:", cookies_dict)
            break
        else:
            print(f"Požadované cookies nejsou dostupné, pokus {attempt + 1}/10. Opakuji za 1 sekundu...")
            time.sleep(1)
    else:
        print("Chyba: Ani po 10 pokusech nebyly získány všechny požadované cookies.")
    
    #driver.save_screenshot("/sdcard/download/screenshot.png")
    #print("Please check screenshot image")

    # Zavře prohlížeč
    driver.quit()

    return cookies_dict if datr and ig_did and mid else None

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
