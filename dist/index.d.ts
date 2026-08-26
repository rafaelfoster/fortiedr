export declare const version = "4.9.5";
export interface ApiSuccess<T = unknown> {
    status: true;
    data: T;
}
export interface ApiFailure {
    status: false;
    data: {
        status_code: number;
        error_message: unknown;
    };
}
export type ApiResult<T = unknown> = ApiSuccess<T> | ApiFailure | string;
export type Params = Record<string, unknown>;
export interface ConnectionOptions {
    host?: string;
    headers?: Record<string, string>;
    enableSSL?: boolean;
    enableDebug?: boolean;
    organization?: string;
}
export declare class FortiEDR_API_GW {
    host: string | null;
    headers: Record<string, string> | null;
    SSL_Verify: boolean;
    debug_enabled: boolean;
    download_folder: string;
    enable_debug(): void;
    conn(headers?: Record<string, string>, host?: string, enable_debug?: boolean, enable_ssl?: boolean, _organization?: string): void;
    get(url: string, params?: Params, request_type?: string, async_req?: boolean): Promise<ApiResult>;
    send(url: string, params?: unknown, request_type?: string, async_req?: boolean): Promise<ApiResult>;
    insert(url: string, params?: unknown, request_type?: string, async_req?: boolean): Promise<ApiResult>;
    update(url: string, params?: unknown, request_type?: string, async_req?: boolean): Promise<ApiResult>;
    delete(url: string, params?: Params, request_type?: string, async_req?: boolean): Promise<ApiResult>;
    post(url: string, params?: unknown, request_type?: string, async_req?: boolean): Promise<ApiResult>;
    put(url: string, params?: unknown, request_type?: string, async_req?: boolean): Promise<ApiResult>;
    download(url: string, params?: Params, _request_type?: string, file_format?: string, download_folder?: string, async_req?: boolean): Promise<ApiResult>;
    upload(url: string, file: unknown, params?: Params, request_type?: string, async_req?: boolean): Promise<ApiResult>;
    private exec;
    private readResponse;
}
export declare class Auth {
    static convert_to_base64(value: string): string;
    static test_authentication(headers: Record<string, string>, host: string): Promise<[boolean, unknown, Headers | null]>;
    static get_headers(host: string, user: string, pass: string, organization?: string): Promise<[Record<string, string> | null, unknown]>;
}
export declare function ignore_certificate(): void;
export declare function enable_debug(): void;
export declare function set_organization(value: string): void;
export declare function get_connection(): FortiEDR_API_GW | null;
export declare function auth(host: string, user: string, passw: string, org?: string): Promise<{
    status: boolean;
    data: unknown;
}>;
export type Controller = {
    conn?: FortiEDR_API_GW;
    [method: string]: any;
};
export interface ControllerInstance {
    conn: FortiEDR_API_GW;
    [method: string]: any;
}
export type ControllerConstructor<T extends ControllerInstance = ControllerInstance> = new (conn?: FortiEDR_API_GW) => T;
export declare const Admin: ControllerConstructor;
export declare const SystemComponents: ControllerConstructor;
export declare const workloadsdeploymentrestapicontroller: ControllerConstructor;
export declare const SystemEvents: ControllerConstructor;
export declare const ApplicationControl: ControllerConstructor;
export declare const AvScannerFileController: ControllerConstructor;
export declare const AvSignatureUpdate: ControllerConstructor;
export declare const CollectorSettings: ControllerConstructor;
export declare const dashboardrestapicontroller: ControllerConstructor;
export declare const DistributionLists: ControllerConstructor;
export declare const exclusionsrestapicontroller: ControllerConstructor;
export declare const Mobile: ControllerConstructor;
export declare const featuresrestapicontroller: ControllerConstructor;
export declare const forensicsrestapicontroller: ControllerConstructor;
export declare const Incidents: ControllerConstructor;
export declare const collectorinventoryrestapicontroller: ControllerConstructor;
export declare const mobileinventoryrestapicontroller: ControllerConstructor;
export declare const workloadslistrestapicontroller: ControllerConstructor;
export declare const notifications: ControllerConstructor;
export declare const policiesrestapicontroller: ControllerConstructor;
export declare const Reputation: ControllerConstructor;
export declare const securebrowserservicerestapicontroller: ControllerConstructor;
export declare const securebrowserrestapicontroller: ControllerConstructor;
export declare const Users: ControllerConstructor;
export declare const Administrator: ControllerConstructor;
export declare const Audit: ControllerConstructor;
export declare const CommunicationControl: ControllerConstructor;
export declare const Events: ControllerConstructor;
export declare const Exceptions: ControllerConstructor;
export declare const Forensics: ControllerConstructor;
export declare const HashSearch: ControllerConstructor;
export declare const Integrations: ControllerConstructor;
export declare const SystemInventory: ControllerConstructor;
export declare const IoT: ControllerConstructor;
export declare const IPsets: ControllerConstructor;
export declare const Organizations: ControllerConstructor;
export declare const Playbookspolicies: ControllerConstructor;
export declare const Policies: ControllerConstructor;
export declare const SendableEntities: ControllerConstructor;
export declare const ExportSettingsSMTP: ControllerConstructor;
export declare const ThreatHuntingExclusions: ControllerConstructor;
export declare const ThreatHuntingSettings: ControllerConstructor;
export declare const ThreatHunting: ControllerConstructor;
export declare const CollectorInventory: ControllerConstructor;
export declare const Dashboard: ControllerConstructor;
export declare const Exclusions: ControllerConstructor;
export declare const ForensicAnalysis: ControllerConstructor;
export declare const IntegrationsSupport: ControllerConstructor;
export declare const Inventory: ControllerConstructor;
export declare const IPSets: ControllerConstructor;
export declare const MobileInventory: ControllerConstructor;
export declare const Notifications: ControllerConstructor;
export declare const PlaybooksPolicies: ControllerConstructor;
export declare const SecureBrowser: ControllerConstructor;
export declare const SecureBrowserService: ControllerConstructor;
export declare const Support: ControllerConstructor;
export declare const Features: ControllerConstructor;
export declare const WorkloadGroups: ControllerConstructor;
export declare const WorkloadsDeployment: ControllerConstructor;
//# sourceMappingURL=index.d.ts.map