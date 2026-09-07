import type { IPv4Network } from "./ip.js";
import type { L2TPCoreConfig, L2TPValidationResult } from "./types.js";
export declare const L2TP_PORT = 1701;
export declare const PSK_MIN_LENGTH = 8;
export declare const PSK_MAX_LENGTH = 128;
export declare const POOL_MIN_PREFIX_LENGTH = 8;
export declare const POOL_MAX_PREFIX_LENGTH = 29;
export declare const DEFAULT_DNS: readonly string[];
export declare const PSK_FORBIDDEN_CHARACTERS: readonly string[];
export declare const L2TP_SCHEMA_ISSUE_CODE = "L2TP_SCHEMA_INVALID_CORE_CONFIG";
export declare const L2TP_TYPE_ISSUE_CODE = "L2TP_TYPE_INVALID_CORE_CONFIG";
export declare const L2TP_VALUE_ISSUE_CODE = "L2TP_VALUE_INVALID_CORE_CONFIG";
export declare function stripWhitespace(value: string): string;
export declare function isValidInboundTag(value: string): boolean;
export declare function normalizeServerAddr(value: string): string | undefined;
export declare function normalizeIPv4(value: string): string | undefined;
export type PoolCheck = {
    readonly ok: true;
    readonly network: IPv4Network;
} | {
    readonly ok: false;
    readonly reason: "required" | "invalid" | "version" | "prefix";
};
export declare function checkPool(value: string): PoolCheck;
export declare function poolFirstHost(network: IPv4Network): string;
export declare function poolContains(network: IPv4Network, address: string): boolean;
export declare function formatPool(network: IPv4Network): string;
export declare function isValidEgressInterface(value: string): boolean;
export declare function normalizeProposal(value: string): string;
export declare function isValidProposal(value: string): boolean;
export type PskProblem = {
    readonly kind: "required";
} | {
    readonly kind: "length";
} | {
    readonly kind: "charset";
} | {
    readonly kind: "forbidden";
    readonly character: string;
};
export declare function inspectPsk(value: string): PskProblem | undefined;
export declare function validateL2TPCoreConfig(input: unknown): L2TPValidationResult;
export declare function assertValidL2TPCoreConfig(input: unknown): L2TPCoreConfig;
export declare function isL2TPCoreConfig(value: unknown): value is L2TPCoreConfig;
//# sourceMappingURL=validation.d.ts.map