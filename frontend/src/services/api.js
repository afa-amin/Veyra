const API_BASE = "/api/v1";

export function getCookie(name) {
  return document.cookie
    .split("; ")
    .find((part) => part.startsWith(`${name}=`))
    ?.split("=")[1] ?? "";
}

async function request(path, options = {}) {
  const method = (options.method || "GET").toUpperCase();
  const headers = new Headers(options.headers || {});

  if (method !== "GET" && method !== "HEAD") {
    const csrf = getCookie("veyra_csrf");
    if (csrf) headers.set("X-CSRF-Token", decodeURIComponent(csrf));
  }

  const response = await fetch(`${API_BASE}${path}`, {
    credentials: "include",
    ...options,
    headers,
  });

  const type = response.headers.get("content-type") || "";
  const payload = type.includes("application/json")
    ? await response.json().catch(() => ({}))
    : await response.text();

  if (!response.ok) {
    const message =
      typeof payload === "object" && payload?.message
        ? payload.message
        : "We couldn't complete this request.";
    const error = new Error(message);
    error.status = response.status;
    error.payload = payload;
    throw error;
  }

  return payload;
}

export const api = {
  get: (path) => request(path),
  post: (path, body) =>
    request(path, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(body ?? {}),
    }),
  delete: (path) => request(path, { method: "DELETE" }),

  upload: async (path, formData, onProgress) => {
    const xhr = new XMLHttpRequest();

    return new Promise((resolve, reject) => {
      xhr.open("POST", `${API_BASE}${path}`);
      xhr.withCredentials = true;

      const csrf = getCookie("veyra_csrf");
      if (csrf) xhr.setRequestHeader("X-CSRF-Token", decodeURIComponent(csrf));

      xhr.upload.onprogress = (event) => {
        if (event.lengthComputable && onProgress) {
          onProgress(Math.round((event.loaded / event.total) * 100));
        }
      };

      xhr.onload = () => {
        const type = xhr.getResponseHeader("content-type") || "";
        let payload = {};
        try {
          payload = type.includes("application/json")
            ? JSON.parse(xhr.responseText)
            : xhr.responseText;
        } catch {
          payload = {};
        }

        if (xhr.status >= 200 && xhr.status < 300) {
          resolve(payload);
        } else {
          reject(new Error(payload?.message || "Upload failed."));
        }
      };

      xhr.onerror = () => reject(new Error("Network error while uploading."));
      xhr.send(formData);
    });
  },
};

export async function downloadBlob(path) {
  const response = await fetch(`${API_BASE}${path}`, {
    credentials: "include",
  });

  if (!response.ok) {
    let message = "Download failed.";
    try {
      const body = await response.json();
      message = body.message || message;
    } catch {}
    throw new Error(message);
  }

  return response.blob();
}
