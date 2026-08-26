import fs from 'node:fs/promises';
import path from 'node:path';
import { Buffer } from 'node:buffer';
import manifest from './generated-manifest.json' with { type: 'json' };

export const version = '4.9.5';

export interface ApiSuccess<T = unknown> { status: true; data: T }
export interface ApiFailure { status: false; data: { status_code: number; error_message: unknown } }
export type ApiResult<T = unknown> = ApiSuccess<T> | ApiFailure | string;
export type Params = Record<string, unknown>;

export interface ConnectionOptions {
  host?: string;
  headers?: Record<string, string>;
  enableSSL?: boolean;
  enableDebug?: boolean;
  organization?: string;
}

function withoutNulls(params: Params = {}): Params {
  return Object.fromEntries(Object.entries(params).filter(([, value]) => value !== null && value !== undefined));
}

function interpolateUrl(template: string, params: Params): { url: string; remaining: Params } {
  const consumed = new Set<string>();
  const url = template.replace(/\{([A-Za-z_]\w*)\}/g, (_match, key: string) => {
    consumed.add(key);
    return encodeURIComponent(String(params[key] ?? ''));
  });
  return { url, remaining: Object.fromEntries(Object.entries(params).filter(([key]) => !consumed.has(key))) };
}

function isObject(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
}

export class FortiEDR_API_GW {
  host: string | null = null;
  headers: Record<string, string> | null = null;
  SSL_Verify = true;
  debug_enabled = false;
  download_folder = '.';

  enable_debug(): void { this.debug_enabled = true; }

  conn(headers?: Record<string, string>, host?: string, enable_debug = false, enable_ssl = true, _organization?: string): void {
    this.headers = headers ?? null;
    this.host = host ?? null;
    this.SSL_Verify = enable_ssl;
    if (enable_debug) this.enable_debug();
  }

  get(url: string, params?: Params, request_type?: string, async_req = false): Promise<ApiResult> { return this.exec('GET', url, params, request_type, async_req); }
  send(url: string, params?: unknown, request_type?: string, async_req = false): Promise<ApiResult> { return this.exec('POST', url, params, request_type, async_req); }
  insert(url: string, params?: unknown, request_type?: string, async_req = false): Promise<ApiResult> { return this.exec('PUT', url, params, request_type, async_req); }
  update(url: string, params?: unknown, request_type?: string, async_req = false): Promise<ApiResult> { return this.exec('PATCH', url, params, request_type, async_req); }
  delete(url: string, params?: Params, request_type?: string, async_req = false): Promise<ApiResult> { return this.exec('DELETE', url, params, request_type, async_req); }
  post(url: string, params?: unknown, request_type?: string, async_req = false): Promise<ApiResult> { return this.send(url, params, request_type, async_req); }
  put(url: string, params?: unknown, request_type?: string, async_req = false): Promise<ApiResult> { return this.insert(url, params, request_type, async_req); }

  async download(url: string, params?: Params, _request_type?: string, file_format = 'zip', download_folder = '.', async_req = false): Promise<ApiResult> {
    this.download_folder = download_folder || '.';
    return this.exec('GET', url, params, undefined, async_req, { download: true, fileFormat: file_format });
  }

  async upload(url: string, file: unknown, params?: Params, request_type?: string, async_req = false): Promise<ApiResult> {
    return this.exec('POST', url, params, request_type, async_req, { upload: file });
  }

  private async exec(method: string, relativeUrl: string, rawParams?: unknown, requestType?: string, asyncReq = false, options: { download?: boolean; fileFormat?: string; upload?: unknown } = {}): Promise<ApiResult> {
    if (asyncReq) return this.exec(method, relativeUrl, rawParams, requestType, false, options);
    if (!this.headers || !this.host) return 'NOT AUTHENTICATED. Run Auth() first.';

    const params = isObject(rawParams) ? withoutNulls(rawParams) : rawParams;
    const resolved = isObject(params) ? interpolateUrl(relativeUrl, params) : { url: relativeUrl, remaining: {} };
    const url = new URL(resolved.url, `https://${this.host}`).toString();
    const headers = { ...this.headers, ...(requestType ? { 'Content-Type': requestType } : {}) };
    const init: RequestInit = { method, headers }; 

    if (method === 'GET' || method === 'DELETE') {
      const query = new URLSearchParams();
      if (isObject(resolved.remaining)) for (const [key, value] of Object.entries(resolved.remaining)) {
        if (Array.isArray(value)) value.forEach((item) => query.append(key, String(item)));
        else query.append(key, String(value));
      }
      const finalUrl = [...query].length ? `${url}${url.includes('?') ? '&' : '?'}${query}` : url;
      if (this.debug_enabled) console.debug('URL =', finalUrl, params);
      try { return this.readResponse(await fetch(finalUrl, init), options); }
      catch (error) { return { status: false, data: { status_code: 500, error_message: error } }; }
    }

    if (options.upload !== undefined) {
      init.body = options.upload as BodyInit;
    } else if (params !== undefined) {
      init.body = JSON.stringify(params);
      headers['Content-Type'] ??= 'application/json';
    }
    if (this.debug_enabled) console.debug('URL =', url, params);
    try { return this.readResponse(await fetch(url, init), options); }
    catch (error) { return { status: false, data: { status_code: 500, error_message: error } }; }
  }

  private async readResponse(response: Response, options: { download?: boolean; fileFormat?: string }): Promise<ApiResult> {
    if (!response.ok) {
      let errorMessage: unknown = await response.text();
      try { errorMessage = (JSON.parse(String(errorMessage)) as { errorMessage?: unknown }).errorMessage ?? errorMessage; } catch { /* plain text */ }
      return { status: false, data: { status_code: response.status, error_message: errorMessage } };
    }
    if (options.download) {
      const name = new URL(response.url).pathname.split('/').pop()?.replaceAll('-', '_') || 'download';
      const filename = path.join(this.download_folder || '.', `${name}_${timestamp()}.${options.fileFormat || 'zip'}`);
      await fs.writeFile(filename, Buffer.from(await response.arrayBuffer()));
      return { status: true, data: filename };
    }
    const text = await response.text();
    try { return { status: true, data: JSON.parse(text) }; } catch { return { status: true, data: text }; }
  }
}

function timestamp(): string {
  const now = new Date();
  const pad = (value: number) => String(value).padStart(2, '0');
  return `${now.getFullYear()}${pad(now.getMonth() + 1)}${pad(now.getDate())}_${pad(now.getHours())}${pad(now.getMinutes())}${pad(now.getSeconds())}`;
}

export class Auth {
  static convert_to_base64(value: string): string { return Buffer.from(value, 'ascii').toString('base64'); }

  static async test_authentication(headers: Record<string, string>, host: string): Promise<[boolean, unknown, Headers | null]> {
    for (const endpoint of ['admin/list-system-summary', 'events/list-events?pageNumber=0&itemsPerPage=1']) {
      try {
        const response = await fetch(`https://${host}/management-rest/${endpoint}`, { headers });
        if (response.status === 401) return [false, 'Unauthorized', null];
        if (response.status === 403) return [false, 'Forbidden', null];
        if (response.status === 404) return [false, 'Not Found', null];
        if (response.status === 500) return [false, 'Internal Server Error', null];
        return [true, response, response.headers];
      } catch (error) { return [false, error, null]; }
    }
    return [false, 'Authentication failed', null];
  }

  static async get_headers(host: string, user: string, pass: string, organization?: string): Promise<[Record<string, string> | null, unknown]> {
    const identity = organization ? `${organization}\\${user}:${pass}` : `${user}:${pass}`;
    const headers = { Authorization: `Basic ${this.convert_to_base64(identity)}` };
    const [status, data] = await this.test_authentication(headers, host);
    return status ? [headers, host] : [null, data];
  }
}

let fortiedr_connection: FortiEDR_API_GW | null = null;
let ssl_enabled = true;
let debug = false;
let organization: string | undefined;

export function ignore_certificate(): void {
  ssl_enabled = false;
  console.warn('[!] - SSL validation cannot be disabled for native Node fetch. Use a trusted certificate.');
}
export function enable_debug(): void { debug = true; }
export function set_organization(value: string): void { organization = value; }
export function get_connection(): FortiEDR_API_GW | null { return fortiedr_connection; }

export async function auth(host: string, user: string, passw: string, org?: string): Promise<{ status: boolean; data: unknown }> {
  const normalizedHost = host.replace(/^https?:\/\//, '').replace(/\/$/, '').split('/')[0];
  if (org) set_organization(org);
  const [headers, result] = await Auth.get_headers(normalizedHost, user, passw, org);
  if (!headers) return { status: false, data: result };
  fortiedr_connection = new FortiEDR_API_GW();
  fortiedr_connection.conn(headers, normalizedHost, debug, ssl_enabled, organization);
  return { status: true, data: 'AUTHENTICATION_SUCCEEDED' };
}

export type Controller = { conn?: FortiEDR_API_GW; [method: string]: any };
type MethodSpec = { params: string[]; method: string; url: string };
type Manifest = { classes: Record<string, Record<string, MethodSpec>> };

function createControllerClass<T extends Controller>(className: string): new (conn?: FortiEDR_API_GW) => T {
  const specs = (manifest as Manifest).classes[className] ?? {};
  class GeneratedController {
    conn: FortiEDR_API_GW;
    constructor(conn?: FortiEDR_API_GW) { this.conn = conn ?? fortiedr_connection ?? new FortiEDR_API_GW(); }
  }
  for (const [name, spec] of Object.entries(specs)) {
    Object.defineProperty(GeneratedController.prototype, name, {
      value: function (this: { conn: FortiEDR_API_GW }, ...args: unknown[]) {
        const params = args.length === 1 && isObject(args[0]) && spec.params.length !== 1
          ? args[0]
          : Object.fromEntries(spec.params.map((param, index) => [param, args[index]]));
        const body = args.length === 1 && isObject(args[0]) && spec.params.length === 1 ? args[0] : params;
        const requestParams = withoutNulls(body);
        const connection = this.conn;
        if (spec.method === 'GET') return connection.get(spec.url, requestParams);
        if (spec.method === 'POST') return connection.send(spec.url, requestParams);
        if (spec.method === 'PUT') return connection.insert(spec.url, requestParams);
        if (spec.method === 'PATCH') return connection.update(spec.url, requestParams);
        return connection.delete(spec.url, requestParams);
      },
      enumerable: false,
    });
  }
  return GeneratedController as unknown as new (conn?: FortiEDR_API_GW) => T;
}

export interface ControllerInstance { conn: FortiEDR_API_GW; [method: string]: any }
export type ControllerConstructor<T extends ControllerInstance = ControllerInstance> = new (conn?: FortiEDR_API_GW) => T;

// These constructors are generated from every Python controller method. Each
// instance accepts an optional connection; omitted connections use the one
// created by auth(). Methods retain the original Python names and endpoints.
export const Admin: ControllerConstructor = createControllerClass('Admin');
export const SystemComponents: ControllerConstructor = createControllerClass('SystemComponents');
export const workloadsdeploymentrestapicontroller: ControllerConstructor = createControllerClass('workloadsdeploymentrestapicontroller');
export const SystemEvents: ControllerConstructor = createControllerClass('SystemEvents');
export const ApplicationControl: ControllerConstructor = createControllerClass('ApplicationControl');
export const AvScannerFileController: ControllerConstructor = createControllerClass('AvScannerFileController');
export const AvSignatureUpdate: ControllerConstructor = createControllerClass('AvSignatureUpdate');
export const CollectorSettings: ControllerConstructor = createControllerClass('CollectorSettings');
export const dashboardrestapicontroller: ControllerConstructor = createControllerClass('dashboardrestapicontroller');
export const DistributionLists: ControllerConstructor = createControllerClass('DistributionLists');
export const exclusionsrestapicontroller: ControllerConstructor = createControllerClass('exclusionsrestapicontroller');
export const Mobile: ControllerConstructor = createControllerClass('Mobile');
export const featuresrestapicontroller: ControllerConstructor = createControllerClass('featuresrestapicontroller');
export const forensicsrestapicontroller: ControllerConstructor = createControllerClass('forensicsrestapicontroller');
export const Incidents: ControllerConstructor = createControllerClass('Incidents');
export const collectorinventoryrestapicontroller: ControllerConstructor = createControllerClass('collectorinventoryrestapicontroller');
export const mobileinventoryrestapicontroller: ControllerConstructor = createControllerClass('mobileinventoryrestapicontroller');
export const workloadslistrestapicontroller: ControllerConstructor = createControllerClass('workloadslistrestapicontroller');
export const notifications: ControllerConstructor = createControllerClass('notifications');
export const policiesrestapicontroller: ControllerConstructor = createControllerClass('policiesrestapicontroller');
export const Reputation: ControllerConstructor = createControllerClass('Reputation');
export const securebrowserservicerestapicontroller: ControllerConstructor = createControllerClass('securebrowserservicerestapicontroller');
export const securebrowserrestapicontroller: ControllerConstructor = createControllerClass('securebrowserrestapicontroller');
export const Users: ControllerConstructor = createControllerClass('Users');
export const Administrator: ControllerConstructor = createControllerClass('Administrator');
export const Audit: ControllerConstructor = createControllerClass('Audit');
export const CommunicationControl: ControllerConstructor = createControllerClass('CommunicationControl');
export const Events: ControllerConstructor = createControllerClass('Events');
export const Exceptions: ControllerConstructor = createControllerClass('Exceptions');
export const Forensics: ControllerConstructor = createControllerClass('Forensics');
export const HashSearch: ControllerConstructor = createControllerClass('HashSearch');
export const Integrations: ControllerConstructor = createControllerClass('Integrations');
export const SystemInventory: ControllerConstructor = createControllerClass('SystemInventory');
export const IoT: ControllerConstructor = createControllerClass('IoT');
export const IPsets: ControllerConstructor = createControllerClass('IPsets');
export const Organizations: ControllerConstructor = createControllerClass('Organizations');
export const Playbookspolicies: ControllerConstructor = createControllerClass('Playbookspolicies');
export const Policies: ControllerConstructor = createControllerClass('Policies');
export const SendableEntities: ControllerConstructor = createControllerClass('SendableEntities');
export const ExportSettingsSMTP: ControllerConstructor = createControllerClass('ExportSettingsSMTP');
export const ThreatHuntingExclusions: ControllerConstructor = createControllerClass('ThreatHuntingExclusions');
export const ThreatHuntingSettings: ControllerConstructor = createControllerClass('ThreatHuntingSettings');
export const ThreatHunting: ControllerConstructor = createControllerClass('ThreatHunting');
export const CollectorInventory: ControllerConstructor = createControllerClass('CollectorInventory');
export const Dashboard: ControllerConstructor = createControllerClass('Dashboard');
export const Exclusions: ControllerConstructor = createControllerClass('Exclusions');
export const ForensicAnalysis: ControllerConstructor = createControllerClass('ForensicAnalysis');
export const IntegrationsSupport: ControllerConstructor = createControllerClass('IntegrationsSupport');
export const Inventory: ControllerConstructor = createControllerClass('Inventory');
export const IPSets: ControllerConstructor = createControllerClass('IPSets');
export const MobileInventory: ControllerConstructor = createControllerClass('MobileInventory');
export const Notifications: ControllerConstructor = createControllerClass('Notifications');
export const PlaybooksPolicies: ControllerConstructor = createControllerClass('PlaybooksPolicies');
export const SecureBrowser: ControllerConstructor = createControllerClass('SecureBrowser');
export const SecureBrowserService: ControllerConstructor = createControllerClass('SecureBrowserService');
export const Support: ControllerConstructor = createControllerClass('Support');
export const Features: ControllerConstructor = createControllerClass('Features');
export const WorkloadGroups: ControllerConstructor = createControllerClass('WorkloadGroups');
export const WorkloadsDeployment: ControllerConstructor = createControllerClass('WorkloadsDeployment');
