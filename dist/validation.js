import { z } from "zod";
import { formatIPv4, formatIPv4Network, isIPAddress, isIPv6, isIPv6Network, networkContains, networkFirstHost, parseIPv4, parseIPv4Network } from "./ip.js";
export const L2TP_PORT = 1701;
export const PSK_MIN_LENGTH = 8;
export const PSK_MAX_LENGTH = 128;
export const POOL_MIN_PREFIX_LENGTH = 8;
export const POOL_MAX_PREFIX_LENGTH = 29;
export const DEFAULT_DNS = ["1.1.1.1", "8.8.8.8"];
export const PSK_FORBIDDEN_CHARACTERS = ['"', "\\", "#", "{", "}"];
export const L2TP_SCHEMA_ISSUE_CODE = "L2TP_SCHEMA_INVALID_CORE_CONFIG";
export const L2TP_TYPE_ISSUE_CODE = "L2TP_TYPE_INVALID_CORE_CONFIG";
export const L2TP_VALUE_ISSUE_CODE = "L2TP_VALUE_INVALID_CORE_CONFIG";
const TAG_RE = /^[A-Za-z0-9][A-Za-z0-9_.-]{0,63}$/;
const PROPOSAL_RE = /^[a-z0-9-]+$/;
const IFACE_RE = /^[A-Za-z0-9._@-]{1,15}$/;
const HOSTNAME_RE = /^(?=.{1,253}$)[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?(?:\.[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?)*$/;
const FORBIDDEN_PSK_CHARACTERS = new Set(PSK_FORBIDDEN_CHARACTERS);
const WHITESPACE = "\\t-\\r\\x1c-\\x1f \\x85\\u00a0\\u1680\\u2000-\\u200a\\u2028\\u2029\\u202f\\u205f\\u3000";
const STRIP_RE = new RegExp(`^[${WHITESPACE}]+|[${WHITESPACE}]+$`, "gu");
const jsonValueSchema = z.lazy(() => z.union([z.string(), z.number().finite(), z.boolean(), z.null(), z.array(jsonValueSchema), z.record(jsonValueSchema)]));
const rawL2TPCoreConfigSchema = z.object({}).catchall(jsonValueSchema);
export function stripWhitespace(value) {
    return value.replace(STRIP_RE, "");
}
function quote(value) {
    if (value.includes("'") && !value.includes('"'))
        return `"${value}"`;
    return `'${value.replace(/\\/g, "\\\\").replace(/'/g, "\\'")}'`;
}
function issue(path, code, message) {
    return { path, code, message };
}
function isStringArray(value) {
    return Array.isArray(value) && value.every(entry => typeof entry === "string");
}
export function isValidInboundTag(value) {
    return TAG_RE.test(value);
}
export function normalizeServerAddr(value) {
    const address = value.replace(/\.+$/, "");
    if (!address)
        return undefined;
    if (isIPAddress(address))
        return address;
    return HOSTNAME_RE.test(address) ? address : undefined;
}
export function normalizeIPv4(value) {
    const address = parseIPv4(stripWhitespace(value));
    return address === undefined ? undefined : formatIPv4(address);
}
export function checkPool(value) {
    const raw = stripWhitespace(value);
    if (!raw)
        return { ok: false, reason: "required" };
    const network = parseIPv4Network(raw);
    if (network === undefined) {
        return { ok: false, reason: isIPv6Network(raw) ? "version" : "invalid" };
    }
    if (network.prefixLength < POOL_MIN_PREFIX_LENGTH || network.prefixLength > POOL_MAX_PREFIX_LENGTH) {
        return { ok: false, reason: "prefix" };
    }
    return { ok: true, network };
}
export function poolFirstHost(network) {
    return formatIPv4(networkFirstHost(network));
}
export function poolContains(network, address) {
    const parsed = parseIPv4(address);
    return parsed !== undefined && networkContains(network, parsed);
}
export function formatPool(network) {
    return formatIPv4Network(network);
}
export function isValidEgressInterface(value) {
    return IFACE_RE.test(value);
}
export function normalizeProposal(value) {
    return stripWhitespace(value).toLowerCase();
}
export function isValidProposal(value) {
    return PROPOSAL_RE.test(value);
}
export function inspectPsk(value) {
    const psk = stripWhitespace(value);
    if (!psk)
        return { kind: "required" };
    const length = Array.from(psk).length;
    if (length < PSK_MIN_LENGTH || length > PSK_MAX_LENGTH)
        return { kind: "length" };
    for (const character of psk) {
        if (!(character > " " && character <= "~"))
            return { kind: "charset" };
        if (FORBIDDEN_PSK_CHARACTERS.has(character))
            return { kind: "forbidden", character };
    }
    return undefined;
}
function requiredString(key, value, issues) {
    if (typeof value !== "string") {
        issues.push(issue(`/${key}`, L2TP_TYPE_ISSUE_CODE, `${key} must be a string`));
        return undefined;
    }
    const stripped = stripWhitespace(value);
    if (!stripped) {
        issues.push(issue(`/${key}`, L2TP_VALUE_ISSUE_CODE, `${key} is required`));
        return undefined;
    }
    return stripped;
}
function optionalString(key, value, issues) {
    if (value === undefined || value === null)
        return "";
    if (typeof value !== "string") {
        issues.push(issue(`/${key}`, L2TP_TYPE_ISSUE_CODE, `${key} must be a string`));
        return undefined;
    }
    return stripWhitespace(value);
}
function normalizeProposals(key, value, issues) {
    if (value === undefined || value === null)
        return [];
    if (!isStringArray(value)) {
        issues.push(issue(`/${key}`, L2TP_TYPE_ISSUE_CODE, `${key} must be a list of strings`));
        return undefined;
    }
    const normalized = [];
    let failed = false;
    value.forEach((entry, index) => {
        const proposal = normalizeProposal(entry);
        if (!proposal)
            return;
        if (!isValidProposal(proposal)) {
            issues.push(issue(`/${key}/${index}`, L2TP_VALUE_ISSUE_CODE, `${key} entry ${quote(proposal)} contains characters strongSwan does not accept`));
            failed = true;
            return;
        }
        normalized.push(proposal);
    });
    return failed ? undefined : normalized;
}
function normalizeDns(value, issues) {
    if (value === undefined || value === null || (Array.isArray(value) && value.length === 0)) {
        return [...DEFAULT_DNS];
    }
    if (!isStringArray(value)) {
        issues.push(issue("/dns", L2TP_TYPE_ISSUE_CODE, "dns must be a list of strings"));
        return undefined;
    }
    const normalized = [];
    let failed = false;
    value.forEach((entry, index) => {
        const stripped = stripWhitespace(entry);
        const address = normalizeIPv4(stripped);
        if (address === undefined) {
            issues.push(issue(`/dns/${index}`, L2TP_VALUE_ISSUE_CODE, `dns entry ${quote(stripped)} must be an IPv4 address`));
            failed = true;
            return;
        }
        normalized.push(address);
    });
    return failed ? undefined : normalized;
}
function normalizeConfig(input) {
    const issues = [];
    const output = Object.create(null);
    for (const key of Object.getOwnPropertyNames(input)) {
        Object.defineProperty(output, key, {
            value: input[key],
            writable: true,
            enumerable: true,
            configurable: true,
        });
    }
    const inboundTag = requiredString("inbound_tag", input.inbound_tag, issues);
    if (inboundTag !== undefined) {
        if (!isValidInboundTag(inboundTag)) {
            issues.push(issue("/inbound_tag", L2TP_VALUE_ISSUE_CODE, "inbound_tag must start with a letter or digit and contain only letters, digits, '_', '.', '-' (max 64)"));
        }
        else {
            output.inbound_tag = inboundTag;
        }
    }
    const serverAddrRaw = requiredString("server_addr", input.server_addr, issues);
    if (serverAddrRaw !== undefined) {
        const trimmed = stripWhitespace(serverAddrRaw).replace(/\.+$/, "");
        if (!trimmed) {
            issues.push(issue("/server_addr", L2TP_VALUE_ISSUE_CODE, "server_addr is required (the public IP or hostname clients connect to)"));
        }
        else {
            const serverAddr = normalizeServerAddr(trimmed);
            if (serverAddr === undefined) {
                issues.push(issue("/server_addr", L2TP_VALUE_ISSUE_CODE, "server_addr must be an IP address or a hostname"));
            }
            else {
                output.server_addr = serverAddr;
            }
        }
    }
    let pool;
    const poolRaw = requiredString("pool", input.pool, issues);
    if (poolRaw !== undefined) {
        const result = checkPool(poolRaw);
        if (result.ok) {
            pool = result.network;
            output.pool = formatPool(result.network);
        }
        else if (result.reason === "version") {
            issues.push(issue("/pool", L2TP_VALUE_ISSUE_CODE, "pool must be an IPv4 network"));
        }
        else if (result.reason === "prefix") {
            issues.push(issue("/pool", L2TP_VALUE_ISSUE_CODE, `pool prefix must be between /${POOL_MIN_PREFIX_LENGTH} and /${POOL_MAX_PREFIX_LENGTH}`));
        }
        else {
            issues.push(issue("/pool", L2TP_VALUE_ISSUE_CODE, `pool ${quote(poolRaw)} is not a valid CIDR`));
        }
    }
    const localIpRaw = optionalString("local_ip", input.local_ip, issues);
    if (localIpRaw !== undefined) {
        const candidate = localIpRaw !== "" ? localIpRaw : pool !== undefined ? poolFirstHost(pool) : undefined;
        if (candidate !== undefined) {
            const localIp = normalizeIPv4(candidate);
            if (localIp === undefined) {
                const insidePoolMessage = isIPv6(candidate) && pool !== undefined;
                issues.push(issue("/local_ip", L2TP_VALUE_ISSUE_CODE, insidePoolMessage && pool !== undefined
                    ? `local_ip must be an IPv4 address inside the pool ${formatPool(pool)}`
                    : "local_ip must be an IPv4 address"));
            }
            else if (pool !== undefined && !poolContains(pool, localIp)) {
                issues.push(issue("/local_ip", L2TP_VALUE_ISSUE_CODE, `local_ip must be an IPv4 address inside the pool ${formatPool(pool)}`));
            }
            else {
                output.local_ip = localIp;
            }
        }
    }
    const egress = optionalString("egress_interface", input.egress_interface, issues);
    if (egress !== undefined) {
        if (egress && !isValidEgressInterface(egress)) {
            issues.push(issue("/egress_interface", L2TP_VALUE_ISSUE_CODE, "egress_interface must be a valid interface name (max 15 chars)"));
        }
        else {
            output.egress_interface = egress;
        }
    }
    const dns = normalizeDns(input.dns, issues);
    if (dns !== undefined)
        output.dns = dns;
    const ikeProposals = normalizeProposals("ike_proposals", input.ike_proposals, issues);
    if (ikeProposals !== undefined)
        output.ike_proposals = ikeProposals;
    const espProposals = normalizeProposals("esp_proposals", input.esp_proposals, issues);
    if (espProposals !== undefined)
        output.esp_proposals = espProposals;
    const legacyClients = input.legacy_clients === undefined ? false : input.legacy_clients;
    if (typeof legacyClients !== "boolean") {
        issues.push(issue("/legacy_clients", L2TP_TYPE_ISSUE_CODE, "legacy_clients must be a boolean"));
    }
    else {
        output.legacy_clients = legacyClients;
    }
    const psk = requiredString("psk", input.psk, issues);
    if (psk !== undefined) {
        const problem = inspectPsk(psk);
        if (problem === undefined) {
            output.psk = psk;
        }
        else if (problem.kind === "length") {
            issues.push(issue("/psk", L2TP_VALUE_ISSUE_CODE, `psk must be between ${PSK_MIN_LENGTH} and ${PSK_MAX_LENGTH} characters`));
        }
        else if (problem.kind === "charset") {
            issues.push(issue("/psk", L2TP_VALUE_ISSUE_CODE, "psk must contain only printable ASCII characters without spaces"));
        }
        else if (problem.kind === "forbidden") {
            issues.push(issue("/psk", L2TP_VALUE_ISSUE_CODE, `psk must not contain ${quote(problem.character)}`));
        }
        else {
            issues.push(issue("/psk", L2TP_VALUE_ISSUE_CODE, "psk is required"));
        }
    }
    if (issues.length > 0)
        return { issues };
    return { config: output, issues };
}
function pathForZod(path) {
    if (path.length === 0)
        return "/";
    return `/${path.map(String).join("/")}`;
}
export function validateL2TPCoreConfig(input) {
    const parsed = rawL2TPCoreConfigSchema.safeParse(input);
    if (!parsed.success) {
        return {
            ok: false,
            issues: parsed.error.issues.map(zodIssue => issue(pathForZod(zodIssue.path.filter((part) => typeof part === "string" || typeof part === "number")), L2TP_SCHEMA_ISSUE_CODE, zodIssue.message))
        };
    }
    const carried = parsed.data;
    if (input !== null && typeof input === "object") {
        for (const key of Object.getOwnPropertyNames(input)) {
            if (Object.getOwnPropertyDescriptor(carried, key) === undefined) {
                Object.defineProperty(carried, key, {
                    value: input[key],
                    writable: true,
                    enumerable: true,
                    configurable: true,
                });
            }
        }
    }
    const { config, issues } = normalizeConfig(carried);
    if (!config)
        return { ok: false, issues };
    return { ok: true, config, issues: [] };
}
export function assertValidL2TPCoreConfig(input) {
    const result = validateL2TPCoreConfig(input);
    if (!result.ok) {
        const firstIssue = result.issues[0];
        throw new Error(firstIssue ? `${firstIssue.path}: ${firstIssue.message}` : "Invalid L2TP core config.");
    }
    return result.config;
}
export function isL2TPCoreConfig(value) {
    if (!value || typeof value !== "object" || Array.isArray(value))
        return false;
    const candidate = value;
    return (typeof candidate.inbound_tag === "string" &&
        typeof candidate.server_addr === "string" &&
        typeof candidate.psk === "string" &&
        typeof candidate.pool === "string");
}
//# sourceMappingURL=validation.js.map