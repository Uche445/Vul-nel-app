document.addEventListener("DOMContentLoaded", () => {
  const html = document.documentElement;
  const body = document.body;
  const themeIcon = document.getElementById("theme-icon");

  if (localStorage.theme === "dark") {
    html.classList.add("dark");
    body.classList.add("dark-mode");
    themeIcon.src = themeIcon.dataset.sun;
  }

  themeIcon.addEventListener("click", () => {
    const isDark = html.classList.toggle("dark");
    body.classList.toggle("dark-mode");
    localStorage.theme = isDark ? "dark" : "light";
    themeIcon.src = isDark ? themeIcon.dataset.sun : themeIcon.dataset.moon;
  });

  const selector = document.getElementById("scanSelector");
  const forms = {
    port: document.getElementById("portForm"),
    brute: document.getElementById("bruteForm"),
    tcp: document.getElementById("tcpForm"),
    ssh: document.getElementById("sshForm")
  };

  selector.addEventListener("change", () => {
    const selected = selector.value;
    for (let key in forms) {
      forms[key].classList.toggle("hidden", key !== selected);
    }
  });

  const scanButton = document.getElementById("startScanBtn");
  scanButton.addEventListener("click", () => {
    for (let key in forms) {
      if (!forms[key].classList.contains("hidden")) {
        forms[key].querySelector("form").requestSubmit();
      }
    }
  });
});
