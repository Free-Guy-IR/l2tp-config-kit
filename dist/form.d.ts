import type { JsonValue, L2TPCoreConfig, L2TPValidationIssue } from "./types.js";
export type L2TPCoreDraft = {
    readonly inboundTag: string;
    readonly serverAddr: string;
    readonly psk: string;
    readonly pool: string;
    readonly localIp: string;
    readonly egressInterface: string;
    readonly dns: string;
    readonly ikeProposals: string;
    readonly espProposals: string;
    readonly legacyClients: boolean;
};
export declare const DEFAULT_POOL = "10.10.10.0/24";
export declare const GENERATED_PSK_LENGTH = 32;
export declare function splitLines(raw: string): string[];
export declare function joinLines(values: readonly string[]): string;
export declare function generateL2TPPsk(): string;
export declare function createDefaultL2TPCoreDraft(): L2TPCoreDraft;
export declare function validateL2TPCoreDraft(draft: L2TPCoreDraft): L2TPValidationIssue[];
export declare function rawL2TPCoreConfigFromDraft(draft: L2TPCoreDraft): Record<string, JsonValue>;
export declare function createL2TPCoreConfigFromDraft(draft: L2TPCoreDraft): L2TPCoreConfig;
export declare function generateL2TPCoreConfigJsonFromDraft(draft: L2TPCoreDraft, space?: number): string;
export declare function l2tpCoreDraftFromConfig(config: L2TPCoreConfig): L2TPCoreDraft;
//# sourceMappingURL=form.d.ts.map