export type IPv4Network = {
    readonly network: number;
    readonly prefixLength: number;
};
export declare function parseIPv4(value: string): number | undefined;
export declare function formatIPv4(value: number): string;
export declare function isIPv6(value: string): boolean;
export declare function isIPAddress(value: string): boolean;
export declare function netmaskFromPrefixLength(prefixLength: number): number;
export declare function parseIPv4Network(value: string): IPv4Network | undefined;
export declare function isIPv6Network(value: string): boolean;
export declare function formatIPv4Network(network: IPv4Network): string;
export declare function networkContains(network: IPv4Network, address: number): boolean;
export declare function networkFirstHost(network: IPv4Network): number;
//# sourceMappingURL=ip.d.ts.map