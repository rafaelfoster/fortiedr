import fs from 'node:fs/promises';
import path from 'node:path';
import { Buffer } from 'node:buffer';
import manifest from './generated-manifest.json' with { type: 'json' };
export const version = '4.9.5';
function withoutNulls(params = {}) {
    return Object.fromEntries(Object.entries(params).filter(([, value]) => value !== null && value !== undefined));
}
function interpolateUrl(template, params) {
    const consumed = new Set();
    const url = template.replace(/\{([A-Za-z_]\w*)\}/g, (_match, key) => {
        consumed.add(key);
        return encodeURIComponent(String(params[key] ?? ''));
    });
    return { url, remaining: Object.fromEntries(Object.entries(params).filter(([key]) => !consumed.has(key))) };
}
function isObject(value) {
    return typeof value === 'object' && value !== null && !Array.isArray(value);
}
export class FortiEDR_API_GW {
    host = null;
    headers = null;
    SSL_Verify = true;
    debug_enabled = false;
    download_folder = '.';
    enable_debug() { this.debug_enabled = true; }
    conn(headers, host, enable_debug = false, enable_ssl = true, _organization) {
        this.headers = headers ?? null;
        this.host = host ?? null;
        this.SSL_Verify = enable_ssl;
        if (enable_debug)
            this.enable_debug();
    }
    get(url, params, request_type, async_req = false) { return this.exec('GET', url, params, request_type, async_req); }
    send(url, params, request_type, async_req = false) { return this.exec('POST', url, params, request_type, async_req); }
    insert(url, params, request_type, async_req = false) { return this.exec('PUT', url, params, request_type, async_req); }
    update(url, params, request_type, async_req = false) { return this.exec('PATCH', url, params, request_type, async_req); }
    delete(url, params, request_type, async_req = false) { return this.exec('DELETE', url, params, request_type, async_req); }
    post(url, params, request_type, async_req = false) { return this.send(url, params, request_type, async_req); }
    put(url, params, request_type, async_req = false) { return this.insert(url, params, request_type, async_req); }
    async download(url, params, _request_type, file_format = 'zip', download_folder = '.', async_req = false) {
        this.download_folder = download_folder || '.';
        return this.exec('GET', url, params, undefined, async_req, { download: true, fileFormat: file_format });
    }
    async upload(url, file, params, request_type, async_req = false) {
        return this.exec('POST', url, params, request_type, async_req, { upload: file });
    }
    async exec(method, relativeUrl, rawParams, requestType, asyncReq = false, options = {}) {
        if (asyncReq)
            return this.exec(method, relativeUrl, rawParams, requestType, false, options);
        if (!this.headers || !this.host)
            return 'NOT AUTHENTICATED. Run Auth() first.';
        const params = isObject(rawParams) ? withoutNulls(rawParams) : rawParams;
        const resolved = isObject(params) ? interpolateUrl(relativeUrl, params) : { url: relativeUrl, remaining: {} };
        const url = new URL(resolved.url, `https://${this.host}`).toString();
        const headers = { ...this.headers, ...(requestType ? { 'Content-Type': requestType } : {}) };
        const init = { method, headers };
        if (method === 'GET' || method === 'DELETE') {
            const query = new URLSearchParams();
            if (isObject(resolved.remaining))
                for (const [key, value] of Object.entries(resolved.remaining)) {
                    if (Array.isArray(value))
                        value.forEach((item) => query.append(key, String(item)));
                    else
                        query.append(key, String(value));
                }
            const finalUrl = [...query].length ? `${url}${url.includes('?') ? '&' : '?'}${query}` : url;
            if (this.debug_enabled)
                console.debug('URL =', finalUrl, params);
            try {
                return this.readResponse(await fetch(finalUrl, init), options);
            }
            catch (error) {
                return { status: false, data: { status_code: 500, error_message: error } };
            }
        }
        if (options.upload !== undefined) {
            init.body = options.upload;
        }
        else if (params !== undefined) {
            init.body = JSON.stringify(params);
            headers['Content-Type'] ??= 'application/json';
        }
        if (this.debug_enabled)
            console.debug('URL =', url, params);
        try {
            return this.readResponse(await fetch(url, init), options);
        }
        catch (error) {
            return { status: false, data: { status_code: 500, error_message: error } };
        }
    }
    async readResponse(response, options) {
        if (!response.ok) {
            let errorMessage = await response.text();
            try {
                errorMessage = JSON.parse(String(errorMessage)).errorMessage ?? errorMessage;
            }
            catch { /* plain text */ }
            return { status: false, data: { status_code: response.status, error_message: errorMessage } };
        }
        if (options.download) {
            const name = new URL(response.url).pathname.split('/').pop()?.replaceAll('-', '_') || 'download';
            const filename = path.join(this.download_folder || '.', `${name}_${timestamp()}.${options.fileFormat || 'zip'}`);
            await fs.writeFile(filename, Buffer.from(await response.arrayBuffer()));
            return { status: true, data: filename };
        }
        const text = await response.text();
        try {
            return { status: true, data: JSON.parse(text) };
        }
        catch {
            return { status: true, data: text };
        }
    }
}
function timestamp() {
    const now = new Date();
    const pad = (value) => String(value).padStart(2, '0');
    return `${now.getFullYear()}${pad(now.getMonth() + 1)}${pad(now.getDate())}_${pad(now.getHours())}${pad(now.getMinutes())}${pad(now.getSeconds())}`;
}
export class Auth {
    static convert_to_base64(value) { return Buffer.from(value, 'ascii').toString('base64'); }
    static async test_authentication(headers, host) {
        for (const endpoint of ['admin/list-system-summary', 'events/list-events?pageNumber=0&itemsPerPage=1']) {
            try {
                const response = await fetch(`https://${host}/management-rest/${endpoint}`, { headers });
                if (response.status === 401)
                    return [false, 'Unauthorized', null];
                if (response.status === 403)
                    return [false, 'Forbidden', null];
                if (response.status === 404)
                    return [false, 'Not Found', null];
                if (response.status === 500)
                    return [false, 'Internal Server Error', null];
                return [true, response, response.headers];
            }
            catch (error) {
                return [false, error, null];
            }
        }
        return [false, 'Authentication failed', null];
    }
    static async get_headers(host, user, pass, organization) {
        const identity = organization ? `${organization}\\${user}:${pass}` : `${user}:${pass}`;
        const headers = { Authorization: `Basic ${this.convert_to_base64(identity)}` };
        const [status, data] = await this.test_authentication(headers, host);
        return status ? [headers, host] : [null, data];
    }
}
let fortiedr_connection = null;
let ssl_enabled = true;
let debug = false;
let organization;
export function ignore_certificate() {
    ssl_enabled = false;
    console.warn('[!] - SSL validation cannot be disabled for native Node fetch. Use a trusted certificate.');
}
export function enable_debug() { debug = true; }
export function set_organization(value) { organization = value; }
export function get_connection() { return fortiedr_connection; }
export async function auth(host, user, passw, org) {
    const normalizedHost = host.replace(/^https?:\/\//, '').replace(/\/$/, '').split('/')[0];
    if (org)
        set_organization(org);
    const [headers, result] = await Auth.get_headers(normalizedHost, user, passw, org);
    if (!headers)
        return { status: false, data: result };
    fortiedr_connection = new FortiEDR_API_GW();
    fortiedr_connection.conn(headers, normalizedHost, debug, ssl_enabled, organization);
    return { status: true, data: 'AUTHENTICATION_SUCCEEDED' };
}
function createControllerClass(className) {
    const specs = manifest.classes[className] ?? {};
    class GeneratedController {
        conn;
        constructor(conn) { this.conn = conn ?? fortiedr_connection ?? new FortiEDR_API_GW(); }
    }
    for (const [name, spec] of Object.entries(specs)) {
        Object.defineProperty(GeneratedController.prototype, name, {
            value: function (...args) {
                const params = args.length === 1 && isObject(args[0]) && spec.params.length !== 1
                    ? args[0]
                    : Object.fromEntries(spec.params.map((param, index) => [param, args[index]]));
                const body = args.length === 1 && isObject(args[0]) && spec.params.length === 1 ? args[0] : params;
                const requestParams = withoutNulls(body);
                const connection = this.conn;
                if (spec.method === 'GET')
                    return connection.get(spec.url, requestParams);
                if (spec.method === 'POST')
                    return connection.send(spec.url, requestParams);
                if (spec.method === 'PUT')
                    return connection.insert(spec.url, requestParams);
                if (spec.method === 'PATCH')
                    return connection.update(spec.url, requestParams);
                return connection.delete(spec.url, requestParams);
            },
            enumerable: false,
        });
    }
    return GeneratedController;
}
// These constructors are generated from every Python controller method. Each
// instance accepts an optional connection; omitted connections use the one
// created by auth(). Methods retain the original Python names and endpoints.
export const Admin = createControllerClass('Admin');
export const SystemComponents = createControllerClass('SystemComponents');
export const workloadsdeploymentrestapicontroller = createControllerClass('workloadsdeploymentrestapicontroller');
export const SystemEvents = createControllerClass('SystemEvents');
export const ApplicationControl = createControllerClass('ApplicationControl');
export const AvScannerFileController = createControllerClass('AvScannerFileController');
export const AvSignatureUpdate = createControllerClass('AvSignatureUpdate');
export const CollectorSettings = createControllerClass('CollectorSettings');
export const dashboardrestapicontroller = createControllerClass('dashboardrestapicontroller');
export const DistributionLists = createControllerClass('DistributionLists');
export const exclusionsrestapicontroller = createControllerClass('exclusionsrestapicontroller');
export const Mobile = createControllerClass('Mobile');
export const featuresrestapicontroller = createControllerClass('featuresrestapicontroller');
export const forensicsrestapicontroller = createControllerClass('forensicsrestapicontroller');
export const Incidents = createControllerClass('Incidents');
export const collectorinventoryrestapicontroller = createControllerClass('collectorinventoryrestapicontroller');
export const mobileinventoryrestapicontroller = createControllerClass('mobileinventoryrestapicontroller');
export const workloadslistrestapicontroller = createControllerClass('workloadslistrestapicontroller');
export const notifications = createControllerClass('notifications');
export const policiesrestapicontroller = createControllerClass('policiesrestapicontroller');
export const Reputation = createControllerClass('Reputation');
export const securebrowserservicerestapicontroller = createControllerClass('securebrowserservicerestapicontroller');
export const securebrowserrestapicontroller = createControllerClass('securebrowserrestapicontroller');
export const Users = createControllerClass('Users');
export const Administrator = createControllerClass('Administrator');
export const Audit = createControllerClass('Audit');
export const CommunicationControl = createControllerClass('CommunicationControl');
export const Events = createControllerClass('Events');
export const Exceptions = createControllerClass('Exceptions');
export const Forensics = createControllerClass('Forensics');
export const HashSearch = createControllerClass('HashSearch');
export const Integrations = createControllerClass('Integrations');
export const SystemInventory = createControllerClass('SystemInventory');
export const IoT = createControllerClass('IoT');
export const IPsets = createControllerClass('IPsets');
export const Organizations = createControllerClass('Organizations');
export const Playbookspolicies = createControllerClass('Playbookspolicies');
export const Policies = createControllerClass('Policies');
export const SendableEntities = createControllerClass('SendableEntities');
export const ExportSettingsSMTP = createControllerClass('ExportSettingsSMTP');
export const ThreatHuntingExclusions = createControllerClass('ThreatHuntingExclusions');
export const ThreatHuntingSettings = createControllerClass('ThreatHuntingSettings');
export const ThreatHunting = createControllerClass('ThreatHunting');
export const CollectorInventory = createControllerClass('CollectorInventory');
export const Dashboard = createControllerClass('Dashboard');
export const Exclusions = createControllerClass('Exclusions');
export const ForensicAnalysis = createControllerClass('ForensicAnalysis');
export const IntegrationsSupport = createControllerClass('IntegrationsSupport');
export const Inventory = createControllerClass('Inventory');
export const IPSets = createControllerClass('IPSets');
export const MobileInventory = createControllerClass('MobileInventory');
export const Notifications = createControllerClass('Notifications');
export const PlaybooksPolicies = createControllerClass('PlaybooksPolicies');
export const SecureBrowser = createControllerClass('SecureBrowser');
export const SecureBrowserService = createControllerClass('SecureBrowserService');
export const Support = createControllerClass('Support');
export const Features = createControllerClass('Features');
export const WorkloadGroups = createControllerClass('WorkloadGroups');
export const WorkloadsDeployment = createControllerClass('WorkloadsDeployment');
