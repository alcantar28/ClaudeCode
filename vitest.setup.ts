import { vi } from "vitest";

// Mock server-only to allow importing in test environment
vi.mock("server-only", () => ({
  default: {},
}));
