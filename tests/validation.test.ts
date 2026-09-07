import { describe, expect, test } from "bun:test";
import {
  assertValidL2TPCoreConfig,
  L2TP_SCHEMA_ISSUE_CODE,
  L2TP_TYPE_ISSUE_CODE,
  L2TP_VALUE_ISSUE_CODE,
  validateL2TPCoreConfig
} from "../src/index.js";

const base = {
  inbound_tag: "L2TP",
  server_addr: "vpn.example.com",
  psk: "S3cretPsk-1234",
  pool: "10.10.10.0/24"
};

function withBase(overrides: Record<string, unknown>): Record<string, unknown> {
  return { ...base, ...overrides };
}

function firstIssue(input: unknown) {
  const result = validateL2TPCoreConfig(input);
  expect(result.ok).toBe(false);
  if (result.ok) throw new Error("expected the config to be rejected");
  return result.issues[0]!;
}

describe("valid configs", () => {
  test("a minimal config round-trips with every default filled in", () => {
    const result = validateL2TPCoreConfig(base);
    expect(result.ok).toBe(true);
    if (!result.ok) return;
    expect(result.config).toEqual({
      inbound_tag: "L2TP",
      server_addr: "vpn.example.com",
      psk: "S3cretPsk-1234",
      pool: "10.10.10.0/24",
      local_ip: "10.10.10.1",
      egress_interface: "",
      dns: ["1.1.1.1", "8.8.8.8"],
      ike_proposals: [],
      esp_proposals: [],
      legacy_clients: false
    });
  });

  test("a fully specified config keeps its values and normalises them", () => {
    const result = validateL2TPCoreConfig({
      inbound_tag: "  L2TP.main-1  ",
      server_addr: " vpn.example.com. ",
      psk: "  S3cretPsk-1234  ",
      pool: "10.10.10.37/24",
      local_ip: " 10.10.10.9 ",
      egress_interface: " eth0 ",
      dns: [" 8.8.4.4 ", "1.0.0.1"],
      ike_proposals: [" AES256-SHA256-MODP2048 ", ""],
      esp_proposals: ["AES256-SHA256"],
      legacy_clients: true
    });
    expect(result.ok).toBe(true);
    if (!result.ok) return;
    expect(result.config).toEqual({
      inbound_tag: "L2TP.main-1",
      server_addr: "vpn.example.com",
      psk: "S3cretPsk-1234",
      pool: "10.10.10.0/24",
      local_ip: "10.10.10.9",
      egress_interface: "eth0",
      dns: ["8.8.4.4", "1.0.0.1"],
      ike_proposals: ["aes256-sha256-modp2048"],
      esp_proposals: ["aes256-sha256"],
      legacy_clients: true
    });
  });

  test("unknown keys are preserved the way the Python dict subclass preserves them", () => {
    const result = validateL2TPCoreConfig({ ...base, note: "kept", extra: { nested: [1, true, null] } });
    expect(result.ok).toBe(true);
    if (!result.ok) return;
    expect(result.config.note).toBe("kept");
    expect(result.config.extra).toEqual({ nested: [1, true, null] });
  });

  test("server_addr accepts IPv4, IPv6 and hostnames", () => {
    for (const serverAddr of ["1.2.3.4", "::1", "2001:db8::1", "vpn.example.com", "a", "x-1.y2.example"]) {
      expect(validateL2TPCoreConfig(withBase({ server_addr: serverAddr })).ok).toBe(true);
    }
  });

  test("an empty dns list falls back to the panel defaults", () => {
    const result = validateL2TPCoreConfig(withBase({ dns: [] }));
    expect(result.ok).toBe(true);
    if (!result.ok) return;
    expect(result.config.dns).toEqual(["1.1.1.1", "8.8.8.8"]);
  });

  test("proposals may be empty so the node applies its own defaults", () => {
    const result = validateL2TPCoreConfig(withBase({ ike_proposals: [], esp_proposals: ["", "  "] }));
    expect(result.ok).toBe(true);
    if (!result.ok) return;
    expect(result.config.ike_proposals).toEqual([]);
    expect(result.config.esp_proposals).toEqual([]);
  });
});

describe("type problems mirror Python TypeError", () => {
  const cases: Array<[string, Record<string, unknown>, string]> = [
    ["inbound_tag missing", { inbound_tag: undefined }, "/inbound_tag"],
    ["inbound_tag not a string", { inbound_tag: 7 }, "/inbound_tag"],
    ["server_addr missing", { server_addr: undefined }, "/server_addr"],
    ["server_addr not a string", { server_addr: ["1.2.3.4"] }, "/server_addr"],
    ["pool missing", { pool: undefined }, "/pool"],
    ["pool not a string", { pool: 24 }, "/pool"],
    ["local_ip not a string", { local_ip: 10 }, "/local_ip"],
    ["egress_interface not a string", { egress_interface: false }, "/egress_interface"],
    ["dns not a list", { dns: "8.8.8.8" }, "/dns"],
    ["dns not a list of strings", { dns: ["8.8.8.8", 1] }, "/dns"],
    ["ike_proposals not a list", { ike_proposals: "aes256" }, "/ike_proposals"],
    ["esp_proposals not a list of strings", { esp_proposals: [null] }, "/esp_proposals"],
    ["legacy_clients an int", { legacy_clients: 1 }, "/legacy_clients"],
    ["legacy_clients a string", { legacy_clients: "true" }, "/legacy_clients"],
    ["legacy_clients null", { legacy_clients: null }, "/legacy_clients"],
    ["psk missing", { psk: undefined }, "/psk"],
    ["psk not a string", { psk: 12345678 }, "/psk"]
  ];

  for (const [name, overrides, path] of cases) {
    test(name, () => {
      const config = withBase(overrides);
      if (overrides.inbound_tag === undefined && "inbound_tag" in overrides) delete config.inbound_tag;
      if (overrides.server_addr === undefined && "server_addr" in overrides) delete config.server_addr;
      if (overrides.pool === undefined && "pool" in overrides) delete config.pool;
      if (overrides.psk === undefined && "psk" in overrides) delete config.psk;
      const issue = firstIssue(config);
      expect(issue.code).toBe(L2TP_TYPE_ISSUE_CODE);
      expect(issue.path).toBe(path);
    });
  }
});

describe("value problems mirror Python ValueError", () => {
  const cases: Array<[string, Record<string, unknown>, string]> = [
    ["inbound_tag blank", { inbound_tag: "   " }, "/inbound_tag"],
    ["inbound_tag starting with an underscore", { inbound_tag: "_l2tp" }, "/inbound_tag"],
    ["inbound_tag with a space", { inbound_tag: "l2tp main" }, "/inbound_tag"],
    ["inbound_tag longer than 64", { inbound_tag: `a${"b".repeat(64)}` }, "/inbound_tag"],
    ["server_addr blank", { server_addr: "  " }, "/server_addr"],
    ["server_addr only dots", { server_addr: "..." }, "/server_addr"],
    ["server_addr with an underscore", { server_addr: "vpn_example.com" }, "/server_addr"],
    ["server_addr with a scheme", { server_addr: "https://vpn.example.com" }, "/server_addr"],
    ["server_addr with a port", { server_addr: "vpn.example.com:1701" }, "/server_addr"],
    ["pool blank", { pool: " " }, "/pool"],
    ["pool not a CIDR", { pool: "not-a-network" }, "/pool"],
    ["pool with an out of range octet", { pool: "10.10.300.0/24" }, "/pool"],
    ["pool IPv6", { pool: "2001:db8::/64" }, "/pool"],
    ["pool prefix too short", { pool: "10.0.0.0/7" }, "/pool"],
    ["pool prefix too long", { pool: "10.10.10.0/30" }, "/pool"],
    ["pool as a bare host", { pool: "10.10.10.1" }, "/pool"],
    ["local_ip not an address", { local_ip: "not-an-ip" }, "/local_ip"],
    ["local_ip IPv6", { local_ip: "2001:db8::1" }, "/local_ip"],
    ["local_ip outside the pool", { local_ip: "10.10.11.1" }, "/local_ip"],
    ["egress_interface with a slash", { egress_interface: "eth0/1" }, "/egress_interface"],
    ["egress_interface longer than 15", { egress_interface: "a".repeat(16) }, "/egress_interface"],
    ["dns entry not an address", { dns: ["dns.example.com"] }, "/dns/0"],
    ["dns entry IPv6", { dns: ["8.8.8.8", "2001:4860:4860::8888"] }, "/dns/1"],
    ["dns entry with a leading zero octet", { dns: ["08.8.8.8"] }, "/dns/0"],
    ["ike proposal with an underscore", { ike_proposals: ["aes256_sha256"] }, "/ike_proposals/0"],
    ["ike proposal with a bang", { ike_proposals: ["aes256-sha256!"] }, "/ike_proposals/0"],
    ["esp proposal with a slash", { esp_proposals: ["aes256", "aes128/sha1"] }, "/esp_proposals/1"],
    ["psk blank", { psk: "   " }, "/psk"],
    ["psk too short", { psk: "short7c" }, "/psk"],
    ["psk too long", { psk: "a".repeat(129) }, "/psk"],
    ["psk with an inner space", { psk: "abcd efgh" }, "/psk"],
    ["psk with a tab", { psk: "abcd\tefgh" }, "/psk"],
    ["psk with a non ascii character", { psk: "abcdefghé" }, "/psk"],
    ["psk with a double quote", { psk: 'abcdefg"h' }, "/psk"],
    ["psk with a backslash", { psk: "abcdefg\\h" }, "/psk"],
    ["psk with a hash", { psk: "abcdefg#h" }, "/psk"],
    ["psk with an opening brace", { psk: "abcdefg{h" }, "/psk"],
    ["psk with a closing brace", { psk: "abcdefg}h" }, "/psk"]
  ];

  for (const [name, overrides, path] of cases) {
    test(name, () => {
      const issue = firstIssue(withBase(overrides));
      expect(issue.code).toBe(L2TP_VALUE_ISSUE_CODE);
      expect(issue.path).toBe(path);
    });
  }

  test("the psk forbidden-character message names the character", () => {
    expect(firstIssue(withBase({ psk: "abcdefg#h" })).message).toBe("psk must not contain '#'");
    expect(firstIssue(withBase({ psk: 'abcdefg"h' })).message).toBe("psk must not contain '\"'");
    expect(firstIssue(withBase({ psk: "abcdefg\\h" })).message).toBe("psk must not contain '\\\\'");
  });

  test("the pool messages distinguish CIDR, family and prefix range", () => {
    expect(firstIssue(withBase({ pool: "nope" })).message).toBe("pool 'nope' is not a valid CIDR");
    expect(firstIssue(withBase({ pool: "2001:db8::/64" })).message).toBe("pool must be an IPv4 network");
    expect(firstIssue(withBase({ pool: "10.0.0.0/30" })).message).toBe("pool prefix must be between /8 and /29");
  });
});

describe("schema problems", () => {
  for (const input of [null, "a string", 42, [], [{ inbound_tag: "L2TP" }], true]) {
    test(`rejects ${JSON.stringify(input)}`, () => {
      const issue = firstIssue(input);
      expect(issue.code).toBe(L2TP_SCHEMA_ISSUE_CODE);
    });
  }
});

describe("the pool and local_ip relationship", () => {
  test("local_ip defaults to the first host of the pool", () => {
    for (const [pool, expected] of [
      ["10.10.10.0/24", "10.10.10.1"],
      ["10.0.0.0/8", "10.0.0.1"],
      ["192.168.99.8/29", "192.168.99.9"],
      ["172.16.4.0/22", "172.16.4.1"]
    ] as const) {
      const result = validateL2TPCoreConfig(withBase({ pool }));
      expect(result.ok).toBe(true);
      if (!result.ok) return;
      expect(result.config.local_ip).toBe(expected);
    }
  });

  test("host bits are masked off before the first host is derived", () => {
    const result = validateL2TPCoreConfig(withBase({ pool: "192.168.99.13/29", local_ip: "" }));
    expect(result.ok).toBe(true);
    if (!result.ok) return;
    expect(result.config.pool).toBe("192.168.99.8/29");
    expect(result.config.local_ip).toBe("192.168.99.9");
  });

  test("the network and broadcast addresses count as inside the pool", () => {
    for (const localIp of ["10.10.10.0", "10.10.10.255", "10.10.10.1", "10.10.10.254"]) {
      expect(validateL2TPCoreConfig(withBase({ local_ip: localIp })).ok).toBe(true);
    }
  });

  test("an address one step outside the pool is rejected", () => {
    for (const localIp of ["10.10.9.255", "10.10.11.0", "10.11.10.1", "127.0.0.1"]) {
      const issue = firstIssue(withBase({ local_ip: localIp }));
      expect(issue.path).toBe("/local_ip");
      expect(issue.message).toBe("local_ip must be an IPv4 address inside the pool 10.10.10.0/24");
    }
  });

  test("the widest and narrowest accepted prefixes are /8 and /29", () => {
    expect(validateL2TPCoreConfig(withBase({ pool: "10.0.0.0/8" })).ok).toBe(true);
    expect(validateL2TPCoreConfig(withBase({ pool: "10.10.10.0/29" })).ok).toBe(true);
    expect(validateL2TPCoreConfig(withBase({ pool: "10.0.0.0/7" })).ok).toBe(false);
    expect(validateL2TPCoreConfig(withBase({ pool: "10.10.10.0/30" })).ok).toBe(false);
  });
});

describe("assertValidL2TPCoreConfig", () => {
  test("returns the normalised config", () => {
    expect(assertValidL2TPCoreConfig(base).local_ip).toBe("10.10.10.1");
  });

  test("throws the first issue as path plus message", () => {
    expect(() => assertValidL2TPCoreConfig(withBase({ pool: "nope" }))).toThrow("/pool: pool 'nope' is not a valid CIDR");
  });
});
