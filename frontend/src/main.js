import { api } from "./services/api.js";
import { store } from "./state/store.js";
import { renderLoading, renderErrorPage } from "./components/layout.js";
import { homePage } from "./pages/home.js";
import { authPage } from "./pages/auth.js";
import { dashboardPage } from "./pages/dashboard.js";
import { transfersPage } from "./pages/transfers.js";
import { sendPage } from "./pages/send.js";
import { transferPage } from "./pages/transfer.js";
import { settingsPage } from "./pages/settings.js";
import { downloadPage } from "./pages/download.js";
import { legalPage } from "./pages/legal.js";
import "./styles.css";

async function loadUser() {
  if (store.get().loadingUser) return store.get().user;

  store.set({ loadingUser: true });

  try {
    const user = await api.get("/me");
    store.set({ user, loadingUser: false });
    return user;
  } catch {
    store.set({ user: null, loadingUser: false });
    return null;
  }
}

function route() {
  const raw = location.hash.replace(/^#\/?/, "");
  return raw.split("/").filter(Boolean);
}

async function renderRoute() {
  renderLoading();

  const parts = route();
  const [name, id] = parts;
  const publicDownload = name === "download";

  let user = null;
  if (!publicDownload) user = await loadUser();

  if (publicDownload && id) {
    await downloadPage(id);
    return;
  }

  try {
    if (!name) {
      homePage(user);
      return;
    }

    if (name === "login") {
      if (user) {
        location.hash = "#/dashboard";
        return;
      }
      authPage("login");
      return;
    }

    if (name === "register") {
      if (user) {
        location.hash = "#/dashboard";
        return;
      }
      authPage("register");
      return;
    }

    if (!user) {
      location.hash = `#/login`;
      return;
    }

    switch (name) {
      case "dashboard":
        await dashboardPage(user);
        break;
      case "send":
        sendPage(user);
        break;
      case "transfers":
        if (id) {
          await transferPage(user, id);
        } else {
          await transfersPage(user);
        }
        break;
      case "settings":
        settingsPage(user);
        break;
      case "security":
      case "privacy":
      case "terms":
        legalPage(name);
        break;
      default:
        if (name === "transfers" && id) {
          await transferPage(user, id);
        } else if (name === "transfer" && id) {
          await transferPage(user, id);
        } else {
          renderErrorPage("The page you requested does not exist.");
        }
    }
  } catch (error) {
    console.error(error);
    renderErrorPage("An unexpected error occurred.");
  }
}

window.addEventListener("hashchange", renderRoute);
window.addEventListener("DOMContentLoaded", renderRoute);
