// Per-tab session. sessionStorage (not localStorage) so one browser can hold an
// employee in one tab and the SOC analyst in another -- which is the demo.

export type Kind = "employee" | "soc";

export interface Profile {
  username: string;
  kind: Kind;
  role: string;
  city: string;
  device?: string;
}

export interface StoredSession {
  token: string;
  kind: Kind;
  profile: Profile;
}

const KEY = "lookout.session";

export function loadSession(): StoredSession | null {
  try {
    const raw = sessionStorage.getItem(KEY);
    return raw ? (JSON.parse(raw) as StoredSession) : null;
  } catch {
    return null;
  }
}

export function saveSession(s: StoredSession): void {
  try {
    sessionStorage.setItem(KEY, JSON.stringify(s));
  } catch {
    /* storage unavailable: session lives only in memory for this page */
  }
}

export function clearSession(): void {
  try {
    sessionStorage.removeItem(KEY);
  } catch {
    /* nothing to clear */
  }
}

export function token(): string | null {
  return loadSession()?.token ?? null;
}
