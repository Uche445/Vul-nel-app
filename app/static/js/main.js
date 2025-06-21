document.addEventListener("DOMContentLoaded", () => {
  function fetchLogs() {
    fetch('/logs')
      .then(response => response.json())
      .then(data => {
        const logList = document.getElementById('scanLogList');
        if (logList) {
          logList.innerHTML = '';
          data.logs.forEach(line => {
            const li = document.createElement('li');
            li.textContent = line.trim();
            logList.appendChild(li);
          });
        }
      })
      .catch(err => console.error('Error fetching logs:', err));
  }

  setInterval(fetchLogs, 5000);
  fetchLogs();

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

  function triggerAutoScan() {
    const progressBar = document.getElementById("autoScanProgress");
    const toast = document.getElementById("scanPhaseToast");
    if (progressBar) {
      progressBar.classList.remove("hidden");
      progressBar.value = 0;
    }
    if (toast) {
      toast.classList.remove("hidden");
      toast.textContent = "🔍 Auto Scan started...";
    }

    fetch("/auto-scan", { method: "POST" })
      .then(() => {
        const interval = setInterval(() => {
          fetch("/auto-scan/progress")
            .then(res => res.json())
            .then(data => {
              if (progressBar) {
                progressBar.value = data.progress;
              }
              if (toast) {
                toast.textContent = `🔄 Auto Scan Progress: ${data.progress}%`;
              }
              if (data.progress >= 100) {
                clearInterval(interval);
                if (toast) toast.classList.add("hidden");
                const completeToast = document.getElementById("autoScanToast");
                if (completeToast) completeToast.classList.remove("hidden");
                setTimeout(() => {
                  window.location.reload();
                }, 2000);
              }
            });
        }, 1000);
      })
      .catch(err => console.error("Auto scan failed:", err));
  }

  const scanButton = document.getElementById("startScanBtn");
  scanButton.addEventListener("click", triggerAutoScan);

  // ✅ Auto-trigger scan on page load
  triggerAutoScan();
});
