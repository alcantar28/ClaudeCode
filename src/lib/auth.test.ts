import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";
import { createSession } from "./auth";

// Mock jose
vi.mock("jose", () => {
  const mockSign = vi.fn();
  return {
    SignJWT: vi.fn().mockImplementation(() => ({
      setProtectedHeader: vi.fn().mockReturnThis(),
      setExpirationTime: vi.fn().mockReturnThis(),
      setIssuedAt: vi.fn().mockReturnThis(),
      sign: mockSign,
    })),
    jwtVerify: vi.fn(),
  };
});

// Mock next/headers
vi.mock("next/headers", () => {
  const mockCookieStore = {
    set: vi.fn(),
    get: vi.fn(),
    delete: vi.fn(),
  };
  return {
    cookies: vi.fn().mockResolvedValue(mockCookieStore),
  };
});

describe("createSession", () => {
  let mockSignJWT: any;
  let mockCookies: any;
  let mockCookieStore: any;

  beforeEach(() => {
    vi.clearAllMocks();

    // Get mocks
    const { SignJWT } = require("jose");
    const { cookies } = require("next/headers");

    mockSignJWT = SignJWT;
    mockCookies = cookies;
    mockCookieStore = {
      set: vi.fn(),
      get: vi.fn(),
      delete: vi.fn(),
    };

    // Setup mocks
    mockCookies.mockResolvedValue(mockCookieStore);

    // Mock the sign method to return a token
    const mockInstance = mockSignJWT.mock.results[0]?.value;
    if (mockInstance) {
      mockInstance.sign.mockResolvedValue("mock-jwt-token");
    }
  });

  afterEach(() => {
    vi.restoreAllMocks();
  });

  it("should create a session with correct payload", async () => {
    const { SignJWT } = require("jose");
    const mockToken = "mock-jwt-token";

    // Setup mock to capture the payload
    let capturedPayload: any;
    SignJWT.mockImplementation((payload) => {
      capturedPayload = payload;
      return {
        setProtectedHeader: vi.fn().mockReturnThis(),
        setExpirationTime: vi.fn().mockReturnThis(),
        setIssuedAt: vi.fn().mockReturnThis(),
        sign: vi.fn().mockResolvedValue(mockToken),
      };
    });

    const userId = "user-123";
    const email = "test@example.com";

    await createSession(userId, email);

    expect(capturedPayload).toMatchObject({
      userId,
      email,
    });
    expect(capturedPayload.expiresAt).toBeInstanceOf(Date);
  });

  it("should set expiration time to 7 days", async () => {
    const { SignJWT } = require("jose");
    let mockInstance: any;

    SignJWT.mockImplementation((payload) => {
      mockInstance = {
        setProtectedHeader: vi.fn().mockReturnThis(),
        setExpirationTime: vi.fn().mockReturnThis(),
        setIssuedAt: vi.fn().mockReturnThis(),
        sign: vi.fn().mockResolvedValue("mock-token"),
      };
      return mockInstance;
    });

    await createSession("user-123", "test@example.com");

    expect(mockInstance.setExpirationTime).toHaveBeenCalledWith("7d");
  });

  it("should set JWT header algorithm to HS256", async () => {
    const { SignJWT } = require("jose");
    let mockInstance: any;

    SignJWT.mockImplementation((payload) => {
      mockInstance = {
        setProtectedHeader: vi.fn().mockReturnThis(),
        setExpirationTime: vi.fn().mockReturnThis(),
        setIssuedAt: vi.fn().mockReturnThis(),
        sign: vi.fn().mockResolvedValue("mock-token"),
      };
      return mockInstance;
    });

    await createSession("user-123", "test@example.com");

    expect(mockInstance.setProtectedHeader).toHaveBeenCalledWith({
      alg: "HS256",
    });
  });

  it("should set issued at time on JWT", async () => {
    const { SignJWT } = require("jose");
    let mockInstance: any;

    SignJWT.mockImplementation((payload) => {
      mockInstance = {
        setProtectedHeader: vi.fn().mockReturnThis(),
        setExpirationTime: vi.fn().mockReturnThis(),
        setIssuedAt: vi.fn().mockReturnThis(),
        sign: vi.fn().mockResolvedValue("mock-token"),
      };
      return mockInstance;
    });

    await createSession("user-123", "test@example.com");

    expect(mockInstance.setIssuedAt).toHaveBeenCalled();
  });

  it("should store token in httpOnly cookie with correct options", async () => {
    const { SignJWT } = require("jose");
    const mockToken = "mock-jwt-token";

    SignJWT.mockImplementation((payload) => ({
      setProtectedHeader: vi.fn().mockReturnThis(),
      setExpirationTime: vi.fn().mockReturnThis(),
      setIssuedAt: vi.fn().mockReturnThis(),
      sign: vi.fn().mockResolvedValue(mockToken),
    }));

    await createSession("user-123", "test@example.com");

    const cookieCall = mockCookieStore.set.mock.calls[0];
    expect(cookieCall[0]).toBe("auth-token");
    expect(cookieCall[1]).toBe(mockToken);
    expect(cookieCall[2]).toMatchObject({
      httpOnly: true,
      sameSite: "lax",
      path: "/",
    });
  });

  it("should set secure flag based on NODE_ENV", async () => {
    const { SignJWT } = require("jose");
    const originalEnv = process.env.NODE_ENV;

    try {
      SignJWT.mockImplementation((payload) => ({
        setProtectedHeader: vi.fn().mockReturnThis(),
        setExpirationTime: vi.fn().mockReturnThis(),
        setIssuedAt: vi.fn().mockReturnThis(),
        sign: vi.fn().mockResolvedValue("mock-token"),
      }));

      // Test production
      process.env.NODE_ENV = "production";
      await createSession("user-123", "test@example.com");

      let cookieCall = mockCookieStore.set.mock.calls[
        mockCookieStore.set.mock.calls.length - 1
      ];
      expect(cookieCall[2].secure).toBe(true);

      mockCookieStore.set.mockClear();

      // Test development
      process.env.NODE_ENV = "development";
      await createSession("user-123", "test@example.com");

      cookieCall = mockCookieStore.set.mock.calls[0];
      expect(cookieCall[2].secure).toBe(false);
    } finally {
      process.env.NODE_ENV = originalEnv;
    }
  });

  it("should set cookie expiration to 7 days from now", async () => {
    const { SignJWT } = require("jose");
    const beforeTime = Date.now();

    SignJWT.mockImplementation((payload) => ({
      setProtectedHeader: vi.fn().mockReturnThis(),
      setExpirationTime: vi.fn().mockReturnThis(),
      setIssuedAt: vi.fn().mockReturnThis(),
      sign: vi.fn().mockResolvedValue("mock-token"),
    }));

    await createSession("user-123", "test@example.com");

    const afterTime = Date.now();
    const cookieCall = mockCookieStore.set.mock.calls[0];
    const cookieExpires = cookieCall[2].expires;

    const sevenDaysInMs = 7 * 24 * 60 * 60 * 1000;
    const expectedMinExpiry = beforeTime + sevenDaysInMs;
    const expectedMaxExpiry = afterTime + sevenDaysInMs;

    expect(cookieExpires.getTime()).toBeGreaterThanOrEqual(expectedMinExpiry);
    expect(cookieExpires.getTime()).toBeLessThanOrEqual(expectedMaxExpiry);
  });

  it("should handle both userId and email correctly", async () => {
    const { SignJWT } = require("jose");
    let capturedPayload: any;

    SignJWT.mockImplementation((payload) => {
      capturedPayload = payload;
      return {
        setProtectedHeader: vi.fn().mockReturnThis(),
        setExpirationTime: vi.fn().mockReturnThis(),
        setIssuedAt: vi.fn().mockReturnThis(),
        sign: vi.fn().mockResolvedValue("mock-token"),
      };
    });

    const userId = "usr_abc123";
    const email = "alice@company.com";

    await createSession(userId, email);

    expect(capturedPayload.userId).toBe(userId);
    expect(capturedPayload.email).toBe(email);
  });
});
