import type { CreateL2TPCoreConfigOptions, CreateL2TPCorePayloadOptions, JsonValue, L2TPCoreConfig, L2TPCorePayload } from "./types.js";
export declare function buildRawL2TPCoreConfig(options: CreateL2TPCoreConfigOptions): Record<string, JsonValue>;
export declare function createL2TPCoreConfig(options: CreateL2TPCoreConfigOptions): L2TPCoreConfig;
export declare function generateL2TPCoreConfigJson(options: CreateL2TPCoreConfigOptions, space?: number): string;
export declare function createL2TPCorePayload(options: CreateL2TPCorePayloadOptions): L2TPCorePayload;
//# sourceMappingURL=core.d.ts.map