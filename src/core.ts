import { assertValidL2TPCoreConfig, DEFAULT_DNS } from "./validation.js";
import type {
  CreateL2TPCoreConfigOptions,
  CreateL2TPCorePayloadOptions,
  JsonValue,
  L2TPCoreConfig,
  L2TPCorePayload
} from "./types.js";

export function buildRawL2TPCoreConfig(options: CreateL2TPCoreConfigOptions): Record<string, JsonValue> {
  return {
    inbound_tag: options.inboundTag,
    server_addr: options.serverAddr,
    psk: options.psk,
    pool: options.pool,
    local_ip: options.localIp ?? "",
    egress_interface: options.egressInterface ?? "",
    dns: [...(options.dns ?? DEFAULT_DNS)],
    ike_proposals: [...(options.ikeProposals ?? [])],
    esp_proposals: [...(options.espProposals ?? [])],
    legacy_clients: options.legacyClients ?? false
  };
}

export function createL2TPCoreConfig(options: CreateL2TPCoreConfigOptions): L2TPCoreConfig {
  return assertValidL2TPCoreConfig(buildRawL2TPCoreConfig(options));
}

export function generateL2TPCoreConfigJson(options: CreateL2TPCoreConfigOptions, space = 2): string {
  return JSON.stringify(createL2TPCoreConfig(options), null, space);
}

export function createL2TPCorePayload(options: CreateL2TPCorePayloadOptions): L2TPCorePayload {
  const { name = "l2tp_core", ...configOptions } = options;
  return {
    name,
    type: "l2tp",
    config: createL2TPCoreConfig(configOptions),
    exclude_inbound_tags: [],
    fallbacks_inbound_tags: []
  };
}
