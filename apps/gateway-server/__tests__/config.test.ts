/**
 * NOSIH Gateway Server — Configuration tests.
 */

import { describe, it, expect, beforeEach, afterEach } from "vitest";
import { loadConfig } from "../src/config.js";

describe("Configuration", () => {
  const originalEnv = { ...process.env };

  beforeEach(() => {
    // Clear all NOSIH env vars
    delete process.env.NOSIH_PORT;
    delete process.env.NOSIH_ENV;
    delete process.env.NODE_ENV;
    delete process.env.NOSIH_STORE;
    delete process.env.NOSIH_CACHE;
    delete process.env.DATABASE_URL;
    delete process.env.REDIS_URL;
    delete process.env.NOSIH_API_KEY;
    delete process.env.NOSIH_REQUIRE_SIGNATURES;
    delete process.env.NOSIH_RATE_LIMIT;
    delete process.env.NOSIH_WS_ALLOW_QUERY_API_KEY;
  });

  afterEach(() => {
    process.env = { ...originalEnv };
  });

  it("loads defaults when no env vars set", () => {
    const config = loadConfig();
    expect(config.env).toBe("development");
    expect(config.port).toBe(3100);
    expect(config.store).toBe("memory");
    expect(config.cache).toBe("memory");
    expect(config.requireSignatures).toBe(false);
    expect(config.rateLimitMax).toBe(100);
    expect(config.wsAllowQueryApiKey).toBe(true);
    expect(config.apiKey).toBeUndefined();
  });

  it("reads env var overrides", () => {
    process.env.NOSIH_ENV = "test";
    process.env.NOSIH_PORT = "8080";
    process.env.NOSIH_API_KEY = "my-key";
    process.env.NOSIH_REQUIRE_SIGNATURES = "true";
    process.env.NOSIH_RATE_LIMIT = "50";
    process.env.NOSIH_WS_ALLOW_QUERY_API_KEY = "false";

    const config = loadConfig();
    expect(config.env).toBe("test");
    expect(config.port).toBe(8080);
    expect(config.apiKey).toBe("my-key");
    expect(config.requireSignatures).toBe(true);
    expect(config.rateLimitMax).toBe(50);
    expect(config.wsAllowQueryApiKey).toBe(false);
  });

  it("throws when NOSIH_STORE=postgres without DATABASE_URL", () => {
    process.env.NOSIH_STORE = "postgres";
    expect(() => loadConfig()).toThrow("DATABASE_URL is required");
  });

  it("throws when NOSIH_CACHE=redis without REDIS_URL", () => {
    process.env.NOSIH_CACHE = "redis";
    expect(() => loadConfig()).toThrow("REDIS_URL is required");
  });

  it("throws on invalid numeric env vars", () => {
    process.env.NOSIH_PORT = "0";
    expect(() => loadConfig()).toThrow("NOSIH_PORT must be a positive integer");

    process.env.NOSIH_PORT = "3100";
    process.env.NOSIH_RATE_LIMIT = "abc";
    expect(() => loadConfig()).toThrow("NOSIH_RATE_LIMIT must be a positive integer");
  });

  it("throws on invalid boolean env vars", () => {
    process.env.NOSIH_REQUIRE_SIGNATURES = "yes";
    expect(() => loadConfig()).toThrow('NOSIH_REQUIRE_SIGNATURES must be "true" or "false"');
  });

  it("requires durable stores and auth hardening in production", () => {
    process.env.NOSIH_ENV = "production";
    expect(() => loadConfig()).toThrow("NOSIH_STORE=postgres is required");

    process.env.NOSIH_STORE = "postgres";
    process.env.DATABASE_URL = "postgresql://localhost:5432/nosih";
    expect(() => loadConfig()).toThrow("NOSIH_CACHE=redis is required");

    process.env.NOSIH_CACHE = "redis";
    process.env.REDIS_URL = "redis://localhost:6379";
    expect(() => loadConfig()).toThrow("NOSIH_API_KEY is required");

    process.env.NOSIH_API_KEY = "prod-key";
    expect(() => loadConfig()).toThrow("NOSIH_REQUIRE_SIGNATURES=true is required");

    process.env.NOSIH_REQUIRE_SIGNATURES = "true";
    expect(() => loadConfig()).toThrow("NOSIH_WS_ALLOW_QUERY_API_KEY=false is required");
  });

  it("accepts hardened production config", () => {
    process.env.NODE_ENV = "production";
    process.env.NOSIH_STORE = "postgres";
    process.env.NOSIH_CACHE = "redis";
    process.env.DATABASE_URL = "postgresql://localhost:5432/nosih";
    process.env.REDIS_URL = "redis://localhost:6379";
    process.env.NOSIH_API_KEY = "prod-key";
    process.env.NOSIH_REQUIRE_SIGNATURES = "true";
    process.env.NOSIH_WS_ALLOW_QUERY_API_KEY = "false";

    const config = loadConfig();
    expect(config.env).toBe("production");
    expect(config.store).toBe("postgres");
    expect(config.cache).toBe("redis");
    expect(config.apiKey).toBe("prod-key");
    expect(config.requireSignatures).toBe(true);
    expect(config.wsAllowQueryApiKey).toBe(false);
  });

  it("accepts postgres config with DATABASE_URL", () => {
    process.env.NOSIH_STORE = "postgres";
    process.env.DATABASE_URL = "postgresql://localhost:5432/nosih";
    const config = loadConfig();
    expect(config.store).toBe("postgres");
    expect(config.databaseUrl).toBe("postgresql://localhost:5432/nosih");
  });

  it("accepts redis config with REDIS_URL", () => {
    process.env.NOSIH_CACHE = "redis";
    process.env.REDIS_URL = "redis://localhost:6379";
    const config = loadConfig();
    expect(config.cache).toBe("redis");
    expect(config.redisUrl).toBe("redis://localhost:6379");
  });
});
