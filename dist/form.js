import { buildRawL2TPCoreConfig, createL2TPCoreConfig } from "./core.js";
import { checkPool, DEFAULT_DNS, formatPool, inspectPsk, isValidEgressInterface, isValidInboundTag, isValidProposal, normalizeIPv4, normalizeProposal, normalizeServerAddr, poolContains, POOL_MAX_PREFIX_LENGTH, POOL_MIN_PREFIX_LENGTH, PSK_MAX_LENGTH, PSK_MIN_LENGTH, PSK_FORBIDDEN_CHARACTERS } from "./validation.js";
export const DEFAULT_POOL = "10.10.10.0/24";
export const GENERATED_PSK_LENGTH = 32;
const PSK_ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
function issue(path, code, message) {
    return { path, code, message };
}
export function splitLines(raw) {
    return raw
        .split(/[\s,;]+/)
        .map(entry => entry.trim())
        .filter(Boolean);
}
export function joinLines(values) {
    return values.join("\n");
}
export function generateL2TPPsk() {
    const bytes = new Uint8Array(GENERATED_PSK_LENGTH);
    globalThis.crypto.getRandomValues(bytes);
    let psk = "";
    for (const byte of bytes) {
        psk += PSK_ALPHABET.charAt(byte & 63);
    }
    return psk;
}
export function createDefaultL2TPCoreDraft() {
    return {
        inboundTag: "L2TP",
        serverAddr: "",
        psk: generateL2TPPsk(),
        pool: DEFAULT_POOL,
        localIp: "",
        egressInterface: "",
        dns: joinLines(DEFAULT_DNS),
        ikeProposals: "",
        espProposals: "",
        legacyClients: false
    };
}
function validateProposalsDraft(raw, path, code, label, issues) {
    splitLines(raw).forEach(entry => {
        const proposal = normalizeProposal(entry);
        if (proposal && !isValidProposal(proposal)) {
            issues.push(issue(path, code, `${label} proposal "${entry}" contains characters strongSwan does not accept.`));
        }
    });
}
export function validateL2TPCoreDraft(draft) {
    const issues = [];
    const inboundTag = draft.inboundTag.trim();
    if (!inboundTag) {
        issues.push(issue("/inboundTag", "L2TP_FORM_TAG_REQUIRED", "Inbound tag is required."));
    }
    else if (!isValidInboundTag(inboundTag)) {
        issues.push(issue("/inboundTag", "L2TP_FORM_TAG_INVALID", "Inbound tag must start with a letter or digit and may contain letters, digits, '_', '.' and '-' (max 64 characters)."));
    }
    const serverAddr = draft.serverAddr.trim();
    if (!serverAddr) {
        issues.push(issue("/serverAddr", "L2TP_FORM_SERVER_ADDR_REQUIRED", "Server address is required."));
    }
    else if (normalizeServerAddr(serverAddr) === undefined) {
        issues.push(issue("/serverAddr", "L2TP_FORM_SERVER_ADDR_INVALID", "Server address must be an IP address or a hostname."));
    }
    const pool = checkPool(draft.pool);
    if (!pool.ok) {
        if (pool.reason === "required") {
            issues.push(issue("/pool", "L2TP_FORM_POOL_REQUIRED", "Address pool is required."));
        }
        else if (pool.reason === "version") {
            issues.push(issue("/pool", "L2TP_FORM_POOL_VERSION", "Address pool must be an IPv4 network."));
        }
        else if (pool.reason === "prefix") {
            issues.push(issue("/pool", "L2TP_FORM_POOL_PREFIX", `Address pool prefix must be between /${POOL_MIN_PREFIX_LENGTH} and /${POOL_MAX_PREFIX_LENGTH}.`));
        }
        else {
            issues.push(issue("/pool", "L2TP_FORM_POOL_INVALID", "Address pool must be an IPv4 CIDR such as 10.10.10.0/24."));
        }
    }
    const localIp = draft.localIp.trim();
    if (localIp) {
        const normalized = normalizeIPv4(localIp);
        if (normalized === undefined) {
            issues.push(issue("/localIp", "L2TP_FORM_LOCAL_IP_INVALID", "Local IP must be an IPv4 address."));
        }
        else if (pool.ok && !poolContains(pool.network, normalized)) {
            issues.push(issue("/localIp", "L2TP_FORM_LOCAL_IP_OUTSIDE_POOL", `Local IP must be inside the pool ${formatPool(pool.network)}.`));
        }
    }
    const egressInterface = draft.egressInterface.trim();
    if (egressInterface && !isValidEgressInterface(egressInterface)) {
        issues.push(issue("/egressInterface", "L2TP_FORM_EGRESS_INTERFACE_INVALID", "Egress interface must be a valid interface name (max 15 characters)."));
    }
    splitLines(draft.dns).forEach(entry => {
        if (normalizeIPv4(entry) === undefined) {
            issues.push(issue("/dns", "L2TP_FORM_DNS_INVALID", `DNS entry "${entry}" must be an IPv4 address.`));
        }
    });
    validateProposalsDraft(draft.ikeProposals, "/ikeProposals", "L2TP_FORM_IKE_PROPOSAL_INVALID", "IKE", issues);
    validateProposalsDraft(draft.espProposals, "/espProposals", "L2TP_FORM_ESP_PROPOSAL_INVALID", "ESP", issues);
    const problem = inspectPsk(draft.psk);
    if (problem !== undefined) {
        if (problem.kind === "required") {
            issues.push(issue("/psk", "L2TP_FORM_PSK_REQUIRED", "Pre-shared key is required."));
        }
        else if (problem.kind === "length") {
            issues.push(issue("/psk", "L2TP_FORM_PSK_LENGTH", `Pre-shared key must be between ${PSK_MIN_LENGTH} and ${PSK_MAX_LENGTH} characters.`));
        }
        else if (problem.kind === "charset") {
            issues.push(issue("/psk", "L2TP_FORM_PSK_CHARSET", "Pre-shared key must contain only printable ASCII characters without spaces."));
        }
        else {
            issues.push(issue("/psk", "L2TP_FORM_PSK_FORBIDDEN", `Pre-shared key must not contain ${problem.character} (${PSK_FORBIDDEN_CHARACTERS.join(" ")} are not allowed).`));
        }
    }
    return issues;
}
function optionsFromDraft(draft) {
    return {
        inboundTag: draft.inboundTag.trim(),
        serverAddr: draft.serverAddr.trim(),
        psk: draft.psk,
        pool: draft.pool.trim(),
        localIp: draft.localIp.trim(),
        egressInterface: draft.egressInterface.trim(),
        dns: splitLines(draft.dns),
        ikeProposals: splitLines(draft.ikeProposals),
        espProposals: splitLines(draft.espProposals),
        legacyClients: draft.legacyClients
    };
}
export function rawL2TPCoreConfigFromDraft(draft) {
    return buildRawL2TPCoreConfig(optionsFromDraft(draft));
}
export function createL2TPCoreConfigFromDraft(draft) {
    const issues = validateL2TPCoreDraft(draft);
    if (issues.length > 0) {
        const firstIssue = issues[0];
        throw new Error(`${firstIssue.path}: ${firstIssue.message}`);
    }
    return createL2TPCoreConfig(optionsFromDraft(draft));
}
export function generateL2TPCoreConfigJsonFromDraft(draft, space = 2) {
    return JSON.stringify(createL2TPCoreConfigFromDraft(draft), null, space);
}
export function l2tpCoreDraftFromConfig(config) {
    return {
        inboundTag: config.inbound_tag,
        serverAddr: config.server_addr,
        psk: config.psk,
        pool: config.pool,
        localIp: config.local_ip,
        egressInterface: config.egress_interface,
        dns: joinLines(config.dns),
        ikeProposals: joinLines(config.ike_proposals),
        espProposals: joinLines(config.esp_proposals),
        legacyClients: config.legacy_clients
    };
}
//# sourceMappingURL=form.js.map