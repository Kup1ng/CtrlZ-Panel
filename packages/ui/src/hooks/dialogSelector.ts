// What counts as a dialog in the page, for the two places that have to wait for one or step around one: the shell's shortcuts and the
// admin's focus restore. A toast is an alertdialog too (React Aria gives it role=alertdialog with aria-modal=false, HeroUI marks it
// data-slot=toast). It is not a dialog: the page behind it stays usable, it stays for seconds, and counting it made Ctrl+K do nothing
// while one was on screen (gate-r34-1) and every focus restore wait for the give-up time. One constant, so the two cannot disagree.
export const DIALOG_SELECTOR = '[role="dialog"]:not([data-slot="toast"]), [role="alertdialog"]:not([data-slot="toast"])';

// The same, without the shell's own mobile nav sheet. Below 48rem HeroUI Pro renders the sidebar as a Sheet whose Dialog is a role=dialog
// (class sidebar__mobile-dialog), so the key that opened the sheet met "a dialog is open" and could not close it again (gate-r35-1 to 7).
// The sheet holds no secret and no call in flight, so it is not what the shortcuts wait for. A dialog open beside it, or a popover inside
// it, still counts.
export const DIALOG_SELECTOR_BESIDE_NAV_SHEET = DIALOG_SELECTOR.split(",")
  .map((clause) => `${clause.trim()}:not(.sidebar__mobile-dialog)`)
  .join(", ");
