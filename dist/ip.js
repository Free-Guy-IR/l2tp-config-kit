const IPV4_OCTET_RE = /^(?:0|[1-9][0-9]{0,2})$/;
const IPV6_HEXTET_RE = /^[0-9A-Fa-f]{1,4}$/;
const DECIMAL_RE = /^[0-9]+$/;
const IPV4_ALL_ONES = 0xffffffff;
const IPV4_MAX_PREFIX_LENGTH = 32;
const IPV6_MAX_PREFIX_LENGTH = 128;
const IPV6_HEXTET_COUNT = 8;
export function parseIPv4(value) {
    const parts = value.split(".");
    if (parts.length !== 4)
        return undefined;
    let result = 0;
    for (const part of parts) {
        if (!IPV4_OCTET_RE.test(part))
            return undefined;
        const octet = Number(part);
        if (octet > 255)
            return undefined;
        result = result * 256 + octet;
    }
    return result;
}
export function formatIPv4(value) {
    return `${(value >>> 24) & 255}.${(value >>> 16) & 255}.${(value >>> 8) & 255}.${value & 255}`;
}
export function isIPv6(value) {
    let address = value;
    const scopeSeparator = address.indexOf("%");
    if (scopeSeparator !== -1) {
        const scope = address.slice(scopeSeparator + 1);
        if (!scope || scope.includes("%"))
            return false;
        address = address.slice(0, scopeSeparator);
    }
    if (!address.includes(":"))
        return false;
    const compression = address.indexOf("::");
    let parts;
    if (compression === -1) {
        parts = address.split(":");
    }
    else {
        if (address.indexOf("::", compression + 1) !== -1)
            return false;
        const left = address.slice(0, compression);
        const right = address.slice(compression + 2);
        if (left.endsWith(":") || right.startsWith(":"))
            return false;
        parts = [...(left === "" ? [] : left.split(":")), ...(right === "" ? [] : right.split(":"))];
    }
    const embeddedIPv4Allowed = compression === -1 || address.slice(compression + 2) !== "";
    let hextets = parts.length;
    const last = parts[parts.length - 1];
    if (last !== undefined && last.includes(".")) {
        if (!embeddedIPv4Allowed)
            return false;
        if (parseIPv4(last) === undefined)
            return false;
        parts.pop();
        hextets += 1;
    }
    for (const part of parts) {
        if (!IPV6_HEXTET_RE.test(part))
            return false;
    }
    if (compression === -1)
        return hextets === IPV6_HEXTET_COUNT;
    return hextets < IPV6_HEXTET_COUNT;
}
export function isIPAddress(value) {
    return parseIPv4(value) !== undefined || isIPv6(value);
}
export function netmaskFromPrefixLength(prefixLength) {
    if (prefixLength === 0)
        return 0;
    return (IPV4_ALL_ONES << (IPV4_MAX_PREFIX_LENGTH - prefixLength)) >>> 0;
}
function prefixFromPrefixString(value, maxPrefixLength) {
    if (!DECIMAL_RE.test(value))
        return undefined;
    const prefixLength = Number(value);
    if (!Number.isInteger(prefixLength) || prefixLength < 0 || prefixLength > maxPrefixLength)
        return undefined;
    return prefixLength;
}
function prefixFromNetmask(mask) {
    if (mask === 0)
        return 0;
    let trailingZeroes = 0;
    while (((mask >>> trailingZeroes) & 1) === 0)
        trailingZeroes += 1;
    const prefixLength = IPV4_MAX_PREFIX_LENGTH - trailingZeroes;
    const leadingOnes = mask >>> trailingZeroes;
    return leadingOnes === Math.pow(2, prefixLength) - 1 ? prefixLength : undefined;
}
export function parseIPv4Network(value) {
    const separator = value.indexOf("/");
    const addressText = separator === -1 ? value : value.slice(0, separator);
    const maskText = separator === -1 ? String(IPV4_MAX_PREFIX_LENGTH) : value.slice(separator + 1);
    const address = parseIPv4(addressText);
    if (address === undefined)
        return undefined;
    let prefixLength = prefixFromPrefixString(maskText, IPV4_MAX_PREFIX_LENGTH);
    if (prefixLength === undefined) {
        const mask = parseIPv4(maskText);
        if (mask === undefined)
            return undefined;
        prefixLength = prefixFromNetmask(mask);
        if (prefixLength === undefined)
            prefixLength = prefixFromNetmask((~mask) >>> 0);
        if (prefixLength === undefined)
            return undefined;
    }
    return { network: (address & netmaskFromPrefixLength(prefixLength)) >>> 0, prefixLength };
}
export function isIPv6Network(value) {
    const separator = value.indexOf("/");
    const addressText = separator === -1 ? value : value.slice(0, separator);
    const maskText = separator === -1 ? String(IPV6_MAX_PREFIX_LENGTH) : value.slice(separator + 1);
    if (addressText.includes("%"))
        return false;
    if (!isIPv6(addressText))
        return false;
    return prefixFromPrefixString(maskText, IPV6_MAX_PREFIX_LENGTH) !== undefined;
}
export function formatIPv4Network(network) {
    return `${formatIPv4(network.network)}/${network.prefixLength}`;
}
export function networkContains(network, address) {
    return ((address & netmaskFromPrefixLength(network.prefixLength)) >>> 0) === network.network;
}
export function networkFirstHost(network) {
    return network.network + 1;
}
//# sourceMappingURL=ip.js.map