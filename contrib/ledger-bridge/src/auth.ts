import type { IncomingHttpHeaders } from "node:http";

export function isAuthorized(
  headers: IncomingHttpHeaders | Record<string, string | string[] | undefined>,
  expectedToken: string,
): boolean {
  const token = expectedToken.trim();
  if (!token) return true;

  const raw = headers.authorization;
  if (Array.isArray(raw)) return false;
  return raw === `Bearer ${token}`;
}
