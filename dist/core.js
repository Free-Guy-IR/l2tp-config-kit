import { assertValidL2TPCoreConfig, DEFAULT_DNS } from "./validation.js";
export function buildRawL2TPCoreConfig(options) {
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
export function createL2TPCoreConfig(options) {
    return assertValidL2TPCoreConfig(buildRawL2TPCoreConfig(options));
}
export function generateL2TPCoreConfigJson(options, space = 2) {
    return JSON.stringify(createL2TPCoreConfig(options), null, space);
}
export function createL2TPCorePayload(options) {
    const { name = "l2tp_core", ...configOptions } = options;
    return {
        name,
        type: "l2tp",
        config: createL2TPCoreConfig(configOptions),
        exclude_inbound_tags: [],
        fallbacks_inbound_tags: []
    };
}
//# sourceMappingURL=core.js.map