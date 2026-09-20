import { createHmac, timingSafeEqual } from "crypto";

export const TEST_USER: User = {
  $id: "test-user",
  userId: "test-user",
  email: "test@example.com",
  firstName: "Test",
  lastName: "User",
  name: "Test User",
  address1: "1 Test Street",
  city: "Testville",
  state: "TS",
  postalCode: "00000",
  dateOfBirth: "1990-01-01",
  ssn: "0000",
  dwollaCustomerId: "",
  dwollaCustomerUrl: "",
};

const TEST_SESSION_COOKIE = "test-session";
const TEST_SESSION_TTL_SECONDS = 60 * 60 * 24;

function getSecret() {
  return process.env.TEST_AUTH_SECRET || "local-development-test-secret";
}

function sign(value: string) {
  return createHmac("sha256", getSecret()).update(value).digest("base64url");
}

export function createTestToken() {
  const payload = Buffer.from(
    JSON.stringify({
      sub: TEST_USER.$id,
      exp: Math.floor(Date.now() / 1000) + TEST_SESSION_TTL_SECONDS,
    })
  ).toString("base64url");

  return `${payload}.${sign(payload)}`;
}

export function getTestSessionCookieName() {
  return TEST_SESSION_COOKIE;
}

export function verifyTestToken(token: string | undefined) {
  if (!token) return false;

  const [payload, signature] = token.split(".");
  if (!payload || !signature) return false;

  const expectedSignature = sign(payload);
  const signaturesMatch =
    signature.length === expectedSignature.length &&
    timingSafeEqual(Buffer.from(signature), Buffer.from(expectedSignature));

  if (!signaturesMatch) return false;

  try {
    const parsedPayload = JSON.parse(Buffer.from(payload, "base64url").toString());
    return parsedPayload.sub === TEST_USER.$id && parsedPayload.exp > Math.floor(Date.now() / 1000);
  } catch {
    return false;
  }
}

export { TEST_SESSION_TTL_SECONDS };