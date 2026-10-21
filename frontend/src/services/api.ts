export const API_BASE_URL = "http://127.0.0.1:8010/api";
export const EVENTS_WS_URL = "ws://127.0.0.1:8010/ws/events";

export async function apiRequest<T = any>(
  path: string,
  init?: RequestInit,
): Promise<T> {
  const response = await fetch(`${API_BASE_URL}${path}`, {
    ...init,
    headers: {
      ...(init?.body ? { "Content-Type": "application/json" } : {}),
      ...(init?.headers || {}),
    },
  });

  if (!response.ok) {
    let detail = `HTTP ${response.status}`;
    try {
      const body = await response.json();
      if (body?.detail)
        detail =
          typeof body.detail === "string"
            ? body.detail
            : JSON.stringify(body.detail);
    } catch {
      // Keep the HTTP status as the useful error when an error response has no JSON body.
    }
    throw new Error(detail);
  }
  return response.json() as Promise<T>;
}
