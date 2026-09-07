import { describe, expect, test } from "bun:test";
import {
  GENERATED_PSK_LENGTH,
  generateL2TPPsk,
  inspectPsk,
  PSK_FORBIDDEN_CHARACTERS,
  validateL2TPCoreConfig
} from "../src/index.js";

const base = {
  inbound_tag: "L2TP",
  server_addr: "1.2.3.4",
  pool: "10.10.10.0/24"
};

describe("generated pre-shared keys", () => {
  test("every generated psk passes the panel validator", () => {
    const seen = new Set<string>();
    for (let attempt = 0; attempt < 200; attempt += 1) {
      const psk = generateL2TPPsk();
      seen.add(psk);

      expect(psk).toHaveLength(GENERATED_PSK_LENGTH);
      expect(psk.trim()).toBe(psk);
      expect(inspectPsk(psk)).toBeUndefined();

      for (const character of psk) {
        expect(character.charCodeAt(0)).toBeGreaterThan(32);
        expect(character.charCodeAt(0)).toBeLessThan(127);
        expect(PSK_FORBIDDEN_CHARACTERS).not.toContain(character);
      }

      const result = validateL2TPCoreConfig({ ...base, psk });
      expect(result.ok).toBe(true);
      if (!result.ok) throw new Error(`generated psk rejected: ${result.issues[0]?.message}`);
      expect(result.config.psk).toBe(psk);
    }
    expect(seen.size).toBe(200);
  });

  test("the alphabet never contains a character the validator forbids", () => {
    const alphabet = new Set<string>();
    for (let attempt = 0; attempt < 200; attempt += 1) {
      for (const character of generateL2TPPsk()) alphabet.add(character);
    }
    expect(alphabet.size).toBeGreaterThan(50);
    for (const character of alphabet) {
      expect(/^[A-Za-z0-9_-]$/.test(character)).toBe(true);
    }
  });
});
