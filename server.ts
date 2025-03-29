import { serve } from "https://deno.land/std@0.175.0/http/server.ts";
import * as hex from "https://deno.land/std@0.175.0/encoding/hex.ts";
import Logger from "https://deno.land/x/logger@v1.1.1/logger.ts";

const logger = new Logger();

const encoder = new TextEncoder();
const decoder = new TextDecoder();
const toHexString = (buf) => decoder.decode(hex.encode(new Uint8Array(buf)));

const OUTLINE_SIGNING_KEY = await crypto.subtle.importKey(
  "raw",
  encoder.encode(Deno.env.get("WEBHOOK_SECRET")),
  { name: "HMAC", hash: "SHA-256" },
  false,
  ["sign", "verify"],
);

let KC_TOKEN = null;
const KC_MASTER_URL = `${Deno.env.get("KEYCLOAK_ENDPOINT")}/realms/master`;
const KC_URL = `${Deno.env.get("KEYCLOAK_ENDPOINT")}/admin/realms/${
  Deno.env.get("KEYCLOAK_REALM")
}`;

async function handler(req: Request): Response {
  const url = new URL(req.url);
  if (!(url.pathname === "/webhook" && req.method === "POST")) {
    logger.info("Invalid request path or method");
    return new Response("Invalid request", { status: 400 });
  }
  const body = await req.text();
  logger.info(`Request body: ${body}`);

  try {
    const signature = req.headers.get("Outline-Signature");
    logger.info(`Outline-Signature: ${signature}`);
    await validateSignature(signature, body);
    const payload = JSON.parse(body);
    logger.info(`Parsed payload: ${JSON.stringify(payload)}`);
    const model = payload.payload.model;
    if (payload.event === "users.signin") {
      try {
        logger.info(`Handling signin for user ${model.name} (${model.id})`);
        await handleSignin(payload.payload.model);
      } catch (err) {
        logger.error(
          `Failed to handle signin for user ${model.name} (${model.id}): `,
          err,
        );
        throw err;
      }
    }
    return new Response("OK", {
      status: 200,
    });
  } catch (err) {
    logger.warn(`Invalid request: `, err);
    return new Response("Invalid request", {
      status: 400,
    });
  }
}

logger.info("Listening on http://localhost:8000");
serve(handler);

async function handleSignin(model: any) {
  const userId = model.id;
  const { data: outlineUser } = await outlineRequest("/users.info", {
    id: userId,
  });
  const outlineUserGroupsRes = await outlineRequest("/groups.list", {
    offset: 0,
    limit: 100,
    userId,
  });
  const { data: { groups: outlineUserGroups, groupMemberships } } =
    outlineUserGroupsRes;
  const outlineUserGroupsNames = outlineUserGroups.map((group) => group.name);

  const outlineAllGroupsRes = await outlineRequest("/groups.list", {
    offset: 0,
    limit: 100,
  });
  const { data: { groups: outlineAllGroups } } = outlineAllGroupsRes;
  const outlineAllGroupsNames = outlineAllGroups.map((group) => group.name);

  const keycloakParams = new URLSearchParams();
  keycloakParams.append("email", outlineUser.email);
  const keycloakUserRes = await keycloakRequest(`/users?${keycloakParams}`);
  if (!keycloakUserRes || !Array.isArray(keycloakUserRes)) {
    throw new Error("Invalid keycloak response for user query");
  }
  const keyloakUser = keycloakUserRes[0];
  if (!keyloakUser) {
    throw new Error(`User ${outlineUser.email} not found in Keycloak realm`);
  }
  const keycloakGroups = await keycloakRequest(
    `/users/${keyloakUser.id}/groups`,
  );
  const keycloakGroupsNames = keycloakGroups.map((g) => g.name);

  const groupsToCreate = keycloakGroupsNames.filter((g) =>
    !outlineAllGroupsNames.includes(g)
  );
  const groupsToLeave = outlineUserGroupsNames.filter((g) =>
    !keycloakGroupsNames.includes(g)
  );
  const groupsToJoin = keycloakGroupsNames.filter((g) =>
    !outlineUserGroupsNames.includes(g)
  );

  if (!groupsToCreate.length && !groupsToLeave.length && !groupsToJoin.length) {
    logger.info(`  update user ${outlineUser.email}: no changes needed`);
    return;
  }

  logger.info(
    `  update user ${outlineUser.name} - leave (${groupsToLeave}), join (${groupsToJoin}) create (${groupsToCreate})`,
  );
  for (const name of groupsToCreate) {
    try {
      const { data } = await outlineRequest("/groups.create", { name });
      outlineAllGroups.push(data);
    } catch (err) {
      logger.warn(`failed to create group ${name}: `, err);
    }
  }
  for (const name of groupsToJoin) {
    const group = outlineAllGroups.find((g) => g.name === name);
    if (!group) throw new Error("Invalid group: " + name);
    await outlineRequest("/groups.add_user", { id: group.id, userId });
  }
  for (const name of groupsToLeave) {
    const group = outlineAllGroups.find((g) => g.name === name);
    if (!group) throw new Error("Invalid group: " + name);
    await outlineRequest("/groups.remove_user", { id: group.id, userId });
  }
}

async function outlineRequest(path: string, body: any): Promise<Response> {
  const url = Deno.env.get("OUTLINE_ENDPOINT") + path;
  if (body) body = JSON.stringify(body);
  const response = await fetch(
    url,
    {
      body,
      method: "POST",
      headers: {
        Accept: "application/json",
        "Content-Type": "application/json",
        Authorization: `Bearer ${Deno.env.get("OUTLINE_API_TOKEN")}`,
      },
    },
  );
  const text = await response.text();
  try {
    const json = JSON.parse(text);
    if (!response.ok || !json.ok) {
      throw new Error(json.error + ": " + json.message);
    }
    return json;
  } catch (err) {
    throw new Error("Invalid response: " + text);
  }
}

async function keycloakRequest(path: string, body: any): Promise<Response> {
  if (!KC_TOKEN) {
    const url = `${Deno.env.get("KEYCLOAK_ENDPOINT")}/realms/${Deno.env.get("KEYCLOAK_REALM")}/protocol/openid-connect/token`;
    const data = new URLSearchParams();
    data.append("client_id", Deno.env.get("KEYCLOAK_CLIENT_ID"));
    data.append("client_secret", Deno.env.get("KEYCLOAK_CLIENT_SECRET"));
    data.append("grant_type", "client_credentials");
    const headers = new Headers();
    headers.append("content-type", "application/x-www-form-urlencoded");
    const res = await fetch(url, {
      method: "POST",
      body: data.toString(),
      headers,
    });
    if (res.ok) {
      const data = JSON.parse(await res.text());
      logger.info("Login to Keycloak successful using service account");
      KC_TOKEN = data.access_token;
    } else {
      const text = await res.text();
      logger.error(`Login to Keycloak failed: ${text}`);
      throw new Error("Keycloak request failed: " + text);
    }
  }

  const url = KC_URL + path;
  if (body) body = JSON.stringify(body);
  const method = body ? "POST" : "GET";
  const headers = new Headers();
  headers.append("Authorization", `Bearer ${KC_TOKEN}`);
  headers.append("accept", "application/json");
  if (method === "POST") {
    headers.append("content-type", "application/json");
  }
  const response = await fetch(
    url,
    {
      body,
      method,
      headers,
    },
  );
  const json = await response.json();
  return json;
}

async function validateSignature(outlineSignature: string, payload: string) {
  const [_, signTimestamp, signatureHex] = outlineSignature.match(
    /^t=([0-9]+),s=([0-9a-f]+)$/,
  );
  const payloadData = `${signTimestamp}.${payload}`;
  const payloadBuf = encoder.encode(payloadData);
  const signatureBuf = hex.decode(encoder.encode(signatureHex));
  const result = await crypto.subtle.verify(
    "HMAC",
    OUTLINE_SIGNING_KEY,
    signatureBuf,
    payloadBuf,
  );
  if (result !== true) {
    throw new Error("Invalid signature");
  }
  return true;
}