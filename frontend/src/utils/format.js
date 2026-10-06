export function escapeHtml(value) {
  return String(value ?? "").replace(/[&<>'"]/g, (char) => ({
    "&": "&amp;",
    "<": "&lt;",
    ">": "&gt;",
    "'": "&#39;",
    '"': "&quot;",
  }[char]));
}

export function formatBytes(bytes) {
  if (!Number.isFinite(Number(bytes))) return "—";
  let value = Number(bytes);
  if (value < 1024) return `${value} B`;

  const units = ["KB", "MB", "GB", "TB"];
  let index = -1;
  do {
    value /= 1024;
    index += 1;
  } while (value >= 1024 && index < units.length - 1);

  return `${value.toFixed(value >= 10 ? 0 : 1)} ${units[index]}`;
}

export function formatDate(value) {
  if (!value) return "—";
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) return "—";
  return date.toLocaleString([], {
    dateStyle: "medium",
    timeStyle: "short",
  });
}

export function statusClass(status) {
  return `pill ${String(status || "").toLowerCase()}`;
}

export function humanStatus(status) {
  return String(status || "unknown")
    .replace(/[_-]/g, " ")
    .replace(/\b\w/g, (c) => c.toUpperCase());
}
