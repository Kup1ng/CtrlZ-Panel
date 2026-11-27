import {useState} from "react";

// A form's draft of a value the server holds (a template, a mapping). The draft is compared with what the server holds, by
// `same`, which says when two spellings are one value: "a,b" and "a, b", or text with a trailing space. Three rules that a
// plain `useState(row.x)` and `dirty = draft !== row.x` get wrong (wp10-r2-4):
//   - After a save the form is clean at once, whatever form the server stores the value in, so Save cannot stay on and
//     send the same write again.
//   - A new value from the server (another admin, a refetch) is shown when the admin has not touched the form, and is
//     the new baseline when they have, so their typing is never thrown away and Cancel returns to the server's value.
//   - When the server moved to a value other than the one the admin typed, the form says so (`conflict`) and Save waits for
//     one deliberate act: keep their value, take the server's, or edit the field again. The write has no version or If-Match,
//     so without this it silently replaces another admin's newer value, which can be an emergency limit (wp10-r5-3).

export type ServerDraft<T> = {
  draft: T;
  /** Typing is an answer to a conflict: the admin has the value in front of them. */
  setDraft: (value: T) => void;
  dirty: boolean;
  /** Back to the server's value. */
  reset: () => void;
  /** The server accepted `value`: it is both the draft and the baseline until the server's own answer arrives. */
  saved: (value: T) => void;
  /** The server now holds a value other than the draft, and the admin has not answered yet: Save waits. */
  conflict: boolean;
  /** What the server holds now, for the note. */
  serverValue: T;
  /** The admin saw the other value and keeps their own. */
  keepMine: () => void;
};

export function useServerDraft<T>(server: T, same: (a: T, b: T) => boolean = Object.is): ServerDraft<T> {
  const [draft, setDraftValue] = useState(server);
  const [base, setBase] = useState(server);
  const [seen, setSeen] = useState(server);
  const [conflict, setConflict] = useState(false);

  // Adjusting state while rendering is React's way to follow a prop; the component renders again at once.
  if (!same(seen, server)) {
    setSeen(server);
    setBase(server);
    if (same(draft, base)) {
      setDraftValue(server);
      setConflict(false);
    } else {
      // Typed, and the server moved: it is a conflict unless the server now holds what was typed.
      setConflict(!same(draft, server));
    }
  }

  return {
    draft,
    setDraft: (value) => {
      setDraftValue(value);
      setConflict(false);
    },
    dirty: !same(draft, base),
    reset: () => {
      setDraftValue(base);
      setConflict(false);
    },
    saved: (value) => {
      setBase(value);
      setDraftValue(value);
      setConflict(false);
    },
    conflict,
    serverValue: base,
    keepMine: () => setConflict(false),
  };
}

// A form of several fields (wp10-r4-3). One draft object for the whole form, seeded once, keeps every field it was seeded
// with, including the ones the admin never touched, and the write is built from all of them: the form then undoes what
// another admin changed in a field this admin did not edit (a money cap, the passkey switch, the primary gateway), and both
// see "Saved". So this form holds only what the admin EDITED, as a patch over the server's latest value. The draft is the
// merge, so a field that was not edited always carries what the server holds now, and the body built from the draft carries
// it too. The write is still the whole object where the API replaces the whole object, with the newest values in it.
//
// `same` compares two whole values (it may say two spellings are one value). An edit that is the value the server held when
// the server moved is not kept as an edit: that field follows the server like a field never touched.
//
// A field the admin edited that the server then changed too (wp10-r5-3) is a conflict: the edit is kept, since it is the
// admin's work, but it would replace a newer value, so the form lists it and Save waits for an answer for each one.

export type ServerForm<T extends object> = {
  /** The server's value with the admin's edits on top. Build the write from this, never from a copy of an earlier render. */
  draft: T;
  /** Records edits of some fields; the others stay untouched. Pass only the fields that changed. */
  edit: (fields: Partial<T>) => void;
  dirty: boolean;
  /** Back to the server's value. */
  reset: () => void;
  /** The server accepted `value`: it is the baseline, with no edits left, until the server's own answer arrives. */
  saved: (value: T) => void;
  /**
   * The fields the admin edited and the server then changed too, to something else. Each needs an answer before Save:
   * `keepMine`, `takeServer`, or an edit of that field again.
   */
  conflicts: readonly (keyof T)[];
  /** What the server holds now, for the note under each conflicting field. */
  serverValue: T;
  keepMine: (key: keyof T) => void;
  /** Drop the admin's edit of this field: it follows the server again. */
  takeServer: (key: keyof T) => void;
};

/** Whether putting `value` in the field `key` of `reference` would be a different value (two spellings of one are not). */
function differs<T extends object>(reference: T, key: keyof T, value: T[keyof T] | undefined, same: (a: T, b: T) => boolean): boolean {
  return !same({...reference, [key]: value}, reference);
}

/** The edits that still differ from `reference` (the server value they were made against). */
export function pruneEdits<T extends object>(edits: Partial<T>, reference: T, same: (a: T, b: T) => boolean): Partial<T> {
  const kept: Partial<T> = {};
  for (const key of Object.keys(edits) as (keyof T)[]) {
    if (differs(reference, key, edits[key], same)) kept[key] = edits[key];
  }
  return kept;
}

/**
 * The server moved from `seen` to `server` under an open form. An edit that was only the old value, or is now the value the
 * server holds, goes back to following the server. An edit that is neither is kept, and when the server's own value for that
 * field also changed it is a conflict: the admin's value would replace a newer one.
 */
export function moveEdits<T extends object>(
  edits: Partial<T>,
  seen: T,
  server: T,
  same: (a: T, b: T) => boolean,
): {kept: Partial<T>; conflicts: (keyof T)[]} {
  const kept: Partial<T> = {};
  const conflicts: (keyof T)[] = [];
  for (const key of Object.keys(edits) as (keyof T)[]) {
    const mine = edits[key];
    if (!differs(seen, key, mine, same) || !differs(server, key, mine, same)) continue;
    kept[key] = mine;
    if (differs(seen, key, server[key], same)) conflicts.push(key);
  }
  return {kept, conflicts};
}

export function useServerForm<T extends object>(server: T, same: (a: T, b: T) => boolean): ServerForm<T> {
  const [edits, setEdits] = useState<Partial<T>>({});
  const [seen, setSeen] = useState(server);
  const [confirmed, setConfirmed] = useState<{value: T; from: T} | null>(null);
  const [conflicts, setConflicts] = useState<(keyof T)[]>([]);

  // What the server holds, or what it accepted a moment ago and has not yet said back.
  let base = server;
  if (confirmed) {
    if (same(confirmed.from, server)) base = confirmed.value;
    else setConfirmed(null);
  }
  // Another value arrived: an edit that was only the old value goes back to following the server, the rest stay, and the ones
  // the server changed too are conflicts.
  if (!same(seen, server)) {
    const moved = moveEdits(edits, seen, server, same);
    setSeen(server);
    setEdits(moved.kept);
    setConflicts([...new Set([...conflicts.filter((key) => key in moved.kept), ...moved.conflicts])]);
  }

  const draft = {...base, ...edits};
  return {
    draft,
    edit: (fields) => {
      setEdits((current) => ({...current, ...fields}));
      // Editing the field again is an answer: the admin has it in front of them.
      setConflicts((current) => current.filter((key) => !(key in fields)));
    },
    dirty: !same(draft, base),
    reset: () => {
      setEdits({});
      setConflicts([]);
    },
    saved: (value) => {
      setConfirmed({value, from: server});
      setEdits({});
      setConflicts([]);
    },
    conflicts,
    serverValue: base,
    keepMine: (key) => setConflicts((current) => current.filter((k) => k !== key)),
    takeServer: (key) => {
      setEdits((current) => {
        const next = {...current};
        delete next[key];
        return next;
      });
      setConflicts((current) => current.filter((k) => k !== key));
    },
  };
}
