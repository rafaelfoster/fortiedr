# FortiEDR Python Client

An open-source Python library that wraps the FortiEDR REST API. The client handles authentication, basic HTTP plumbing, and groups endpoints into small Python classes so you can script FortiEDR administration, inventory, threat hunting, and integrations without reimplementing the API calls.

## Installation

The package requires Python 3.8+.

```bash
pip install fortiedr
```

Or install from a local clone:

```bash
git clone https://github.com/rafaelfoster/fortiedr.git
cd fortiedr
pip3 install .
```

## Authenticating

Create a FortiEDR REST API user in the Management console and ensure the user logs in once to change the initial password. Then instantiate the client:

```python
from fortiedr import FortiEDR

fedr = FortiEDR(
    host="your-management-host.example.com",  # hostname only, no https://
    user="api-user",
    password="SuperSecret!",
    organization="ORG_NAME",                  # optional, case sensitive
    enable_debug=False,                       # set True to log request details
    enable_ssl=True                           # set False to skip TLS verification
)

if not fedr.auth["status"]:
    raise SystemExit(f"Authentication failed: {fedr.auth['data']}")
```

The client builds a Basic Auth header, validates it against the FortiEDR gateway, and stores it in `fedr.headers` for subsequent calls.

## Calling the API

All wrapper methods return a dictionary shaped as:

```python
{"status": True|False, "data": <response json|text|error dict>}
```

- `status=True` means the HTTP response was 2xx and JSON (or text) was parsed successfully.
- `status=False` includes `data.status_code` and `data.error_message` with the server reply or Python exception text.

### HTTP helpers on the client

- `get(url, params=None, request_type=None)`
- `send(url, params=None, request_type=None)` – POST
- `insert(url, params=None, request_type=None)` – PUT
- `update(url, params=None, request_type=None)` – PATCH
- `delete(url, params=None, request_type=None)`
- `download(url, params=None, request_type=None, file_format="zip", download_folder="")` writes a file locally and returns its path.
- `upload(url, file, params=None, request_type=None)` sends multipart form data.
- `enable_debug()` activates verbose request logging via `requests`.

Use these helpers directly for endpoints that do not yet have a convenience wrapper.

### Downloading files

`download` streams the response to `<download_folder>/<function>_<timestamp>.<file_format>` and returns that path in `data`.

### Uploading files

`upload` expects a `file` mapping compatible with `requests` (for example, `{"licenseBlob": open("license.lic", "rb")}`) and passes it as multipart form data.

## API surface

The `FortiEDR` instance wires the following wrapper objects as attributes:

- `administrator`, `application_control`, `audit`, `av_scanner_file_controller`, `communication_control`, `events`, `exclusions`, `features`, `forensic_analysis`, `forensics`, `hash_search`, `incidents`, `integrations_support`, `integrations`, `inventory`, `iot`, `ip_sets`, `mobile`, `organizations`, `playbooks_policies`, `policies`, `threat_hunting`, `users`.

Each wrapper exposes a set of methods that map one-to-one to FortiEDR REST endpoints. The complete per-method reference is in `docs/api_reference.md`.

Additional wrappers exist in `fortiedr/api` (for example `SystemComponents`, `Notifications`, `Reputation`), but they are not automatically attached to `FortiEDR` and some of them rely on HTTP verb helpers (`post`, `put`) that are not defined on the current client. See the “Additional/experimental wrappers” section in the API reference for usage notes.

## Examples

See `example.py` for end-to-end snippets that show cloning a policy, listing collectors, fetching incidents, and more. A minimal pattern:

```python
from fortiedr import FortiEDR

fedr = FortiEDR(host="...", user="...", password="...")
events = fedr.events.list_events()
if events["status"]:
    print(events["data"])
else:
    print(events["data"]["error_message"])
```

## Troubleshooting

- Set `enable_debug=True` when constructing `FortiEDR` or call `enable_debug()` later to log URLs, headers, and payloads.
- Pass `enable_ssl=False` only if you explicitly want to skip TLS verification (for lab environments). Production use should keep verification on.
- Authentication errors surface as `{"status": False, "data": "Unauthorized" | "Forbidden" | ...}` from the `Auth.test_authentication` probe.

## Contributing

- Review `docs/api_reference.md` before adding new endpoints so naming stays consistent.
- Prefer reusing the existing HTTP helpers; if an endpoint requires a different verb or content type, add a thin wrapper method to the appropriate class.
- Keep new code ASCII-only unless interacting with existing Unicode data.
