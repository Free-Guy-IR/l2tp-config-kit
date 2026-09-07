export type JsonPrimitive = string | number | boolean | null;
export type JsonValue = JsonPrimitive | JsonObject | JsonValue[];
export type JsonObject = { readonly [key: string]: JsonValue };

export type L2TPCoreConfig = JsonObject & {
  readonly inbound_tag: string;
  readonly server_addr: string;
  readonly psk: string;
  readonly pool: string;
  readonly local_ip: string;
  readonly egress_interface: string;
  readonly dns: readonly string[];
  readonly ike_proposals: readonly string[];
  readonly esp_proposals: readonly string[];
  readonly legacy_clients: boolean;
};

export type L2TPCorePayload = {
  readonly name: string;
  readonly type: "l2tp";
  readonly config: L2TPCoreConfig;
  readonly exclude_inbound_tags: readonly string[];
  readonly fallbacks_inbound_tags: readonly string[];
};

export type CreateL2TPCoreConfigOptions = {
  readonly inboundTag: string;
  readonly serverAddr: string;
  readonly psk: string;
  readonly pool: string;
  readonly localIp?: string;
  readonly egressInterface?: string;
  readonly dns?: readonly string[];
  readonly ikeProposals?: readonly string[];
  readonly espProposals?: readonly string[];
  readonly legacyClients?: boolean;
};

export type CreateL2TPCorePayloadOptions = CreateL2TPCoreConfigOptions & {
  readonly name?: string;
};

export type L2TPValidationIssue = {
  readonly code: string;
  readonly path: string;
  readonly message: string;
};

export type L2TPValidationResult =
  | {
      readonly ok: true;
      readonly config: L2TPCoreConfig;
      readonly issues: readonly [];
    }
  | {
      readonly ok: false;
      readonly issues: readonly L2TPValidationIssue[];
    };
