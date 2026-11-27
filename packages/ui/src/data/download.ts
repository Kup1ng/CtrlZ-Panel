// Saving a file that the page built (the profile document of Export, the rules of Export Rules, the CSV of the Endpoints). It goes
// through a Blob and an `<a download>`: no request is made, and nothing leaves the origin. The object URL is released as soon as the
// click has been handled.

/** A file name that is safe on every system and short: letters of any script, digits, dot, dash and underscore; the rest becomes a dash. */
export function safeFileName(name: string, fallback = "file", max = 60): string {
  const cleaned = name
    .normalize("NFKC")
    .replace(/[^\p{L}\p{N}._-]+/gu, "-")
    .replace(/-{2,}/g, "-")
    .replace(/^[-.]+|[-.]+$/g, "")
    .slice(0, max);
  return cleaned === "" ? fallback : cleaned;
}

export function downloadFile(name: string, content: string, type: string): void {
  const url = URL.createObjectURL(new Blob([content], {type}));
  const link = document.createElement("a");
  link.href = url;
  link.download = name;
  link.rel = "noopener";
  document.body.append(link);
  link.click();
  link.remove();
  setTimeout(() => URL.revokeObjectURL(url), 1000);
}

/** The document is written as the server sent it, indented, with a final newline, so two exports of the same profile are the same bytes. */
export function downloadJson(name: string, value: unknown): void {
  downloadFile(`${safeFileName(name)}.json`, `${JSON.stringify(value, null, 2)}\n`, "application/json;charset=utf-8");
}

/** The CSV of the Endpoints starts with a byte order mark, so a spreadsheet reads Persian names as UTF-8 (the server's file has one; this is for a text we build). */
export function downloadCsv(name: string, content: string): void {
  downloadFile(`${safeFileName(name)}.csv`, content.startsWith("﻿") ? content : `﻿${content}`, "text/csv;charset=utf-8");
}
