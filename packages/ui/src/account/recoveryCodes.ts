// The recovery codes the wizard shows once (spec 12.3): copied as a list and offered as a text file.
// Pure, so a test can see exactly what leaves the page.

export const RECOVERY_FILE_NAME = "ctrlz-recovery-codes.txt";

/** One code per line, nothing else: what the clipboard gets. */
export function recoveryCodesText(codes: readonly string[]): string {
  return codes.join("\n");
}

/**
 * The text file: a short header in the page's language, then the codes. A byte order mark leads, because
 * Windows Notepad otherwise reads a Persian header as ANSI.
 */
export function recoveryFileContent(header: string, codes: readonly string[]): string {
  return `﻿${header}\n\n${recoveryCodesText(codes)}\n`;
}

/**
 * Starts the download through a Blob and an `<a download>`: the codes never leave the page, and no
 * request is made. The object URL is released as soon as the click has been handled.
 */
export function downloadTextFile(name: string, content: string): void {
  const url = URL.createObjectURL(new Blob([content], {type: "text/plain;charset=utf-8"}));
  const link = document.createElement("a");
  link.href = url;
  link.download = name;
  link.rel = "noopener";
  document.body.append(link);
  link.click();
  link.remove();
  setTimeout(() => URL.revokeObjectURL(url), 1000);
}

/** The secret in groups of four for reading aloud or typing: `ABCD EFGH ...`. The copy button copies it without spaces. */
export function groupSecret(secret: string): string {
  return secret.match(/.{1,4}/g)?.join(" ") ?? secret;
}
