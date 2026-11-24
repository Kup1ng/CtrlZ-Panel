"use client";

// Spec 8.7, the fatal state. It replaces the root layout when the layout itself or a provider
// throws, so it has its own <html>. Anything the app normally supplies may be the thing that
// failed, so it supplies none of it: no provider, no message catalogue, no theme, no font file
// and no stylesheet of ours. Both languages are written here, side by side, because nothing can
// say which one the visitor reads. The system font stack and `color-scheme: light dark` stand in
// for the theme, and the colours come from `light-dark()` so a dark phone does not get a white
// flash. Nothing here loads from outside.

const COPY = {
  fa: {
    title: "مشکلی پیش آمد",
    text: "صفحه نتوانست باز شود. دوباره تلاش کنید. اگر ادامه داشت، کد زیر را برای پشتیبانی بفرستید.",
    retry: "تلاش دوباره",
    code: "کد خطا",
  },
  en: {
    title: "Something went wrong",
    text: "The page could not open. Try again. If it keeps happening, send the code below to support.",
    retry: "Try again",
    code: "Error code",
  },
} as const;

const ink = "light-dark(#18181b, #fcfcfc)";
const quiet = "light-dark(#52525b, #a1a1aa)";

export default function GlobalError({error, reset}: {error: Error & {digest?: string}; reset: () => void}) {
  return (
    <html lang="fa" dir="rtl" style={{colorScheme: "light dark"}}>
      <body
        style={{
          margin: 0,
          minHeight: "100dvh",
          display: "grid",
          placeItems: "center",
          padding: 16,
          fontFamily: 'system-ui, "Segoe UI", Tahoma, sans-serif',
          color: ink,
          background: "light-dark(#f7f7f8, #0a0b0c)",
        }}
      >
        <main style={{maxWidth: 420, width: "100%", display: "grid", gap: 24}}>
          {(["fa", "en"] as const).map((lang) => (
            <section key={lang} lang={lang} dir={lang === "fa" ? "rtl" : "ltr"} style={{display: "grid", gap: 8}}>
              <h1 style={{margin: 0, fontSize: 20, fontWeight: 600}}>{COPY[lang].title}</h1>
              <p style={{margin: 0, lineHeight: 1.7, color: quiet}}>{COPY[lang].text}</p>
            </section>
          ))}
          {error.digest ? (
            <p style={{margin: 0, fontSize: 14, color: quiet}} dir="ltr">
              {COPY.fa.code} / {COPY.en.code}: <bdi>{error.digest}</bdi>
            </p>
          ) : null}
          <button
            type="button"
            onClick={() => reset()}
            style={{
              justifySelf: "start",
              minHeight: 44,
              padding: "0 20px",
              border: 0,
              borderRadius: 12,
              font: "inherit",
              fontWeight: 600,
              cursor: "pointer",
              background: "#04b5fb",
              color: "#0a1a22",
            }}
          >
            {COPY.fa.retry} / {COPY.en.retry}
          </button>
        </main>
      </body>
    </html>
  );
}
