const { app, BrowserWindow, dialog, Menu } = require("electron");
const { spawn } = require("child_process");
const fs = require("fs");
const http = require("http");
const path = require("path");

const BACKEND_URL = "http://127.0.0.1:5000";
const HEALTH_URL = `${BACKEND_URL}/health`;

let backendProcess = null;
let backendStartedByElectron = false;

function projectPath(...parts) {
  return path.join(app.getAppPath(), ...parts);
}

function fileExists(filePath) {
  try {
    return fs.existsSync(filePath);
  } catch {
    return false;
  }
}

function findPythonExecutable() {
  const configuredPython = process.env.EVOGUARD_PYTHON_PATH;

  if (configuredPython && fileExists(configuredPython)) {
    return configuredPython;
  }

  const candidates = [
    projectPath(".venv", "Scripts", "python.exe"),
    projectPath("venv", "Scripts", "python.exe"),
    "python",
  ];

  return candidates.find((candidate) => candidate === "python" || fileExists(candidate));
}

function backendIsHealthy() {
  return new Promise((resolve) => {
    const request = http.get(HEALTH_URL, { timeout: 2500 }, (response) => {
      response.resume();
      resolve(response.statusCode >= 200 && response.statusCode < 500);
    });

    request.on("timeout", () => {
      request.destroy();
      resolve(false);
    });

    request.on("error", () => resolve(false));
  });
}

function desktopFrontendIsAvailable() {
  return new Promise((resolve) => {
    let body = "";
    const request = http.get(BACKEND_URL, { timeout: 2500 }, (response) => {
      response.setEncoding("utf8");
      response.on("data", (chunk) => {
        body += chunk;
      });
      response.on("end", () => {
        const contentType = String(response.headers["content-type"] || "");
        resolve(
          response.statusCode === 200 &&
            contentType.includes("text/html") &&
            body.toLowerCase().includes("<!doctype html")
        );
      });
    });

    request.on("timeout", () => {
      request.destroy();
      resolve(false);
    });

    request.on("error", () => resolve(false));
  });
}

async function waitForBackend(timeoutMs = 50000) {
  const startedAt = Date.now();

  while (Date.now() - startedAt < timeoutMs) {
    if (await backendIsHealthy()) {
      return true;
    }

    await new Promise((resolve) => setTimeout(resolve, 1000));
  }

  return false;
}

async function startBackendIfNeeded() {
  if (await backendIsHealthy()) {
    if (await desktopFrontendIsAvailable()) {
      return true;
    }

    dialog.showErrorBox(
      "EvoGuard Backend Already Running",
      "Port 5000 is already running, but it is not serving the desktop app. Stop the old backend first, then open EvoGuard Desktop again."
    );
    return false;
  }

  const pythonExecutable = findPythonExecutable();

  if (!pythonExecutable) {
    dialog.showErrorBox(
      "EvoGuard Backend Not Found",
      "Could not find Python. Install Python or set EVOGUARD_PYTHON_PATH."
    );
    return false;
  }

  const backendDir = projectPath("backend");
  const appPy = path.join(backendDir, "app.py");

  if (!fileExists(appPy)) {
    dialog.showErrorBox(
      "EvoGuard Backend Not Found",
      `Could not find backend app.py at:\n${appPy}`
    );
    return false;
  }

  backendStartedByElectron = true;
  backendProcess = spawn(pythonExecutable, ["app.py"], {
    cwd: backendDir,
    env: {
      ...process.env,
      HOST: "127.0.0.1",
      PORT: "5000",
      EVOGUARD_ENV: "desktop",
      EVOGUARD_SERVE_FRONTEND: "true",
      EVOGUARD_ENABLE_SCHEDULER: "false",
    },
    windowsHide: true,
  });

  backendProcess.on("error", (error) => {
    dialog.showErrorBox("EvoGuard Backend Error", error.message);
  });

  const healthy = await waitForBackend();
  return healthy && (await desktopFrontendIsAvailable());
}

async function createWindow() {
  Menu.setApplicationMenu(null);

  const iconPath = projectPath("EvoGuard-Enterprise.ico");
  const mainWindow = new BrowserWindow({
    width: 1180,
    height: 860,
    minWidth: 980,
    minHeight: 760,
    title: "EvoGuard Enterprise",
    icon: iconPath,
    backgroundColor: "#12001f",
    show: false,
    webPreferences: {
      contextIsolation: true,
      nodeIntegration: false,
    },
  });

  mainWindow.once("ready-to-show", () => {
    mainWindow.setTitle("EvoGuard Enterprise");
    mainWindow.show();
  });

  mainWindow.on("page-title-updated", (event) => {
    event.preventDefault();
    mainWindow.setTitle("EvoGuard Enterprise");
  });

  const backendReady = await startBackendIfNeeded();

  if (!backendReady) {
    dialog.showErrorBox(
      "EvoGuard Backend Did Not Start",
      "The desktop app could not connect to the backend on 127.0.0.1:5000."
    );
    return;
  }

  await mainWindow.loadURL(BACKEND_URL);
}

app.whenReady().then(createWindow);

app.on("window-all-closed", () => {
  if (process.platform !== "darwin") {
    app.quit();
  }
});

app.on("before-quit", () => {
  if (backendStartedByElectron && backendProcess && !backendProcess.killed) {
    backendProcess.kill();
  }
});
