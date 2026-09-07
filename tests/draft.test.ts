import { describe, expect, test } from "bun:test";
import {
  createDefaultL2TPCoreDraft,
  createL2TPCoreConfigFromDraft,
  createL2TPCorePayload,
  generateL2TPCoreConfigJson,
  generateL2TPCoreConfigJsonFromDraft,
  joinLines,
  l2tpCoreDraftFromConfig,
  rawL2TPCoreConfigFromDraft,
  splitLines,
  validateL2TPCoreDraft,
  validateL2TPCoreConfig
} from "../src/index.js";
import type { L2TPCoreDraft } from "../src/index.js";

function completeDraft(overrides: Partial<L2TPCoreDraft> = {}): L2TPCoreDraft {
  return {
    ...createDefaultL2TPCoreDraft(),
    serverAddr: "vpn.example.com",
    ...overrides
  };
}

describe("line helpers", () => {
  test("separators and blank lines are normalised away", () => {
    expect(splitLines("1.1.1.1\n 8.8.8.8,9.9.9.9; 8.8.4.4  ")).toEqual(["1.1.1.1", "8.8.8.8", "9.9.9.9", "8.8.4.4"]);
    expect(splitLines("   ")).toEqual([]);
    expect(joinLines(["1.1.1.1", "8.8.8.8"])).toBe("1.1.1.1\n8.8.8.8");
  });
});

describe("the default draft", () => {
  test("only the server address is missing", () => {
    const draft = createDefaultL2TPCoreDraft();
    const issues = validateL2TPCoreDraft(draft);
    expect(issues).toHaveLength(1);
    expect(issues[0]?.code).toBe("L2TP_FORM_SERVER_ADDR_REQUIRED");
  });

  test("its raw projection never throws and carries the form defaults", () => {
    const raw = rawL2TPCoreConfigFromDraft(createDefaultL2TPCoreDraft());
    expect(raw.inbound_tag).toBe("L2TP");
    expect(raw.server_addr).toBe("");
    expect(raw.pool).toBe("10.10.10.0/24");
    expect(raw.dns).toEqual(["1.1.1.1", "8.8.8.8"]);
    expect(raw.legacy_clients).toBe(false);
    expect(validateL2TPCoreConfig(raw).ok).toBe(false);
  });

  test("filling in the server address makes it saveable", () => {
    const config = createL2TPCoreConfigFromDraft(completeDraft());
    expect(config.server_addr).toBe("vpn.example.com");
    expect(config.local_ip).toBe("10.10.10.1");
    expect(config.dns).toEqual(["1.1.1.1", "8.8.8.8"]);
    expect(config.ike_proposals).toEqual([]);
    expect(config.legacy_clients).toBe(false);
  });
});

describe("draft to config conversion", () => {
  test("multi-line fields become lists and proposals are lowercased", () => {
    const config = createL2TPCoreConfigFromDraft(
      completeDraft({
        inboundTag: " L2TP-main ",
        pool: "10.20.30.40/24",
        localIp: "10.20.30.9",
        egressInterface: "eth0",
        dns: "8.8.8.8\n1.1.1.1",
        ikeProposals: "AES256-SHA256-MODP2048\naes128-sha1-modp1024",
        espProposals: "AES256-SHA256, aes128-sha1",
        legacyClients: true,
        psk: "Draft-Psk-1234"
      })
    );

    expect(config).toEqual({
      inbound_tag: "L2TP-main",
      server_addr: "vpn.example.com",
      psk: "Draft-Psk-1234",
      pool: "10.20.30.0/24",
      local_ip: "10.20.30.9",
      egress_interface: "eth0",
      dns: ["8.8.8.8", "1.1.1.1"],
      ike_proposals: ["aes256-sha256-modp2048", "aes128-sha1-modp1024"],
      esp_proposals: ["aes256-sha256", "aes128-sha1"],
      legacy_clients: true
    });
  });

  test("the generated JSON parses back into the same config", () => {
    const draft = completeDraft({ egressInterface: "ens3" });
    const parsed = JSON.parse(generateL2TPCoreConfigJsonFromDraft(draft)) as Record<string, unknown>;
    expect(parsed).toEqual(createL2TPCoreConfigFromDraft(draft) as unknown as Record<string, unknown>);
  });

  test("a config round-trips back into a draft", () => {
    const draft = completeDraft({
      localIp: "10.10.10.5",
      egressInterface: "eth1",
      dns: "8.8.8.8\n8.8.4.4",
      ikeProposals: "aes256-sha256-modp2048",
      espProposals: "aes256-sha256",
      legacyClients: true
    });
    const config = createL2TPCoreConfigFromDraft(draft);
    expect(l2tpCoreDraftFromConfig(config)).toEqual(draft);
  });

  test("an invalid draft throws its first issue instead of serialising", () => {
    expect(() => createL2TPCoreConfigFromDraft(completeDraft({ serverAddr: "" }))).toThrow(
      "/serverAddr: Server address is required."
    );
    expect(() => createL2TPCoreConfigFromDraft(completeDraft({ pool: "10.0.0.0/30" }))).toThrow("/pool");
  });
});

describe("draft validation", () => {
  const cases: Array<[Partial<L2TPCoreDraft>, string, string]> = [
    [{ inboundTag: "" }, "/inboundTag", "L2TP_FORM_TAG_REQUIRED"],
    [{ inboundTag: "-nope" }, "/inboundTag", "L2TP_FORM_TAG_INVALID"],
    [{ serverAddr: "" }, "/serverAddr", "L2TP_FORM_SERVER_ADDR_REQUIRED"],
    [{ serverAddr: "vpn example.com" }, "/serverAddr", "L2TP_FORM_SERVER_ADDR_INVALID"],
    [{ pool: "" }, "/pool", "L2TP_FORM_POOL_REQUIRED"],
    [{ pool: "nope" }, "/pool", "L2TP_FORM_POOL_INVALID"],
    [{ pool: "2001:db8::/64" }, "/pool", "L2TP_FORM_POOL_VERSION"],
    [{ pool: "10.0.0.0/7" }, "/pool", "L2TP_FORM_POOL_PREFIX"],
    [{ localIp: "nope" }, "/localIp", "L2TP_FORM_LOCAL_IP_INVALID"],
    [{ localIp: "192.168.1.1" }, "/localIp", "L2TP_FORM_LOCAL_IP_OUTSIDE_POOL"],
    [{ egressInterface: "eth0/1" }, "/egressInterface", "L2TP_FORM_EGRESS_INTERFACE_INVALID"],
    [{ dns: "1.1.1.1\nnope" }, "/dns", "L2TP_FORM_DNS_INVALID"],
    [{ ikeProposals: "aes256_sha256" }, "/ikeProposals", "L2TP_FORM_IKE_PROPOSAL_INVALID"],
    [{ espProposals: "aes256!" }, "/espProposals", "L2TP_FORM_ESP_PROPOSAL_INVALID"],
    [{ psk: "" }, "/psk", "L2TP_FORM_PSK_REQUIRED"],
    [{ psk: "short" }, "/psk", "L2TP_FORM_PSK_LENGTH"],
    [{ psk: "abcd efgh" }, "/psk", "L2TP_FORM_PSK_CHARSET"],
    [{ psk: "abcdefg#h" }, "/psk", "L2TP_FORM_PSK_FORBIDDEN"]
  ];

  for (const [overrides, path, code] of cases) {
    test(`${code} at ${path}`, () => {
      const issues = validateL2TPCoreDraft(completeDraft(overrides));
      expect(issues).toHaveLength(1);
      expect(issues[0]?.path).toBe(path);
      expect(issues[0]?.code).toBe(code);
    });
  }

  test("a complete draft has no issues", () => {
    expect(validateL2TPCoreDraft(completeDraft())).toEqual([]);
  });
});

describe("payload helpers", () => {
  test("createL2TPCorePayload builds the panel create-core body", () => {
    const payload = createL2TPCorePayload({
      inboundTag: "L2TP",
      serverAddr: "1.2.3.4",
      psk: "Payload-Psk-1",
      pool: "10.10.10.0/24"
    });
    expect(payload).toEqual({
      name: "l2tp_core",
      type: "l2tp",
      config: {
        inbound_tag: "L2TP",
        server_addr: "1.2.3.4",
        psk: "Payload-Psk-1",
        pool: "10.10.10.0/24",
        local_ip: "10.10.10.1",
        egress_interface: "",
        dns: ["1.1.1.1", "8.8.8.8"],
        ike_proposals: [],
        esp_proposals: [],
        legacy_clients: false
      },
      exclude_inbound_tags: [],
      fallbacks_inbound_tags: []
    });
  });

  test("the payload name can be overridden and the JSON generator agrees", () => {
    const options = {
      name: "l2tp-eu",
      inboundTag: "L2TP",
      serverAddr: "1.2.3.4",
      psk: "Payload-Psk-1",
      pool: "10.10.10.0/24"
    };
    const payload = createL2TPCorePayload(options);
    expect(payload.name).toBe("l2tp-eu");
    expect(JSON.parse(generateL2TPCoreConfigJson(options)) as unknown).toEqual(
      payload.config as unknown as Record<string, unknown>
    );
  });
});
