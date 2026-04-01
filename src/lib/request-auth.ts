import { timingSafeEqual } from "node:crypto"

import type { Context, Next } from "hono"

import { state } from "./state"

const AUTH_ERROR = {
  error: {
    message: "Unauthorized",
    type: "authentication_error",
  },
} as const

const safeEqual = (a: string, b: string) => {
  const left = Buffer.from(a)
  const right = Buffer.from(b)

  if (left.length !== right.length) {
    return false
  }

  return timingSafeEqual(left, right)
}

const extractBearerToken = (authorizationHeader?: string) => {
  if (!authorizationHeader) {
    return undefined
  }

  const [scheme, ...rest] = authorizationHeader.trim().split(/\s+/)
  if (!scheme || scheme.toLowerCase() !== "bearer") {
    return undefined
  }

  const token = rest.join(" ")
  return token.length > 0 ? token : undefined
}

const getProvidedApiKey = (c: Context) => {
  const bearerToken = extractBearerToken(c.req.header("authorization"))

  if (bearerToken) {
    return bearerToken
  }

  const xApiKey = c.req.header("x-api-key")
  return xApiKey?.trim() || undefined
}

export async function requireApiKey(c: Context, next: Next) {
  const configuredApiKey = state.apiKey

  if (!configuredApiKey) {
    return next()
  }

  if (c.req.path === "/" || c.req.method === "OPTIONS") {
    return next()
  }

  const providedApiKey = getProvidedApiKey(c)

  if (!providedApiKey || !safeEqual(providedApiKey, configuredApiKey)) {
    return c.json(AUTH_ERROR, 401)
  }

  return next()
}