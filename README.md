# FortiEDR Python module
An open-source Python package intended to help interact with FortiEDR API.

See [changelog](CHANGELOG.md) for more.

## How do I install the FortiEDR Python module?

Be sure you have at least Python 3.8 and PIP (https://pypi.org/project/pip/) installed.

After downloading this tool, use pip to install dependencies using the following command:

```
pip install fortiedr
```

Or you can download it directly from this repo:

```
git clone https://github.com/rafaelfoster/fortiedr.git

cd fortiedr

pip3 install .
```

## First steps with fortiedr

First of all, create a Rest API user on FortiEDR Management console:
 * Create a user with Rest API permissions on FortiEDR Console. You can check this doc for help: https://docs.fortinet.com/document/fortiedr/6.2.0/administration-guide/776468/users

 * After creating the user, this newly created user must log in to the Central Manager console and change their initial password before they can be used by Rest API calls.

After creating a user with privileges for interacting with FortiEDR API, you can start using the package by importing the modules you want to your code:

`import fortiedr`

Once imported, you need to authenticate with Management Host using valid credentials, as such:

```
organization = "ORGANIZATION_NAME"

authentication = auth(
    user="USER",
    passw="PASSWORD",
    host="FORTIEDR_HOST.COM", # use only the hostname, without 'https://' and '/'.
    org=organization          # Add organization IF needed. Case sensitive
)
```

If the authentication is successful, you can proceed by interacting with the API, like:


```
collectors = fortiedr.Collectors()

data = collectors.list_collectors()

```

## How do I use FortiEDR Python module?

After credentials are defined and successfully authenticated, you are now able to start consuming FortiEDR API.

The "example.py" file contains some examples of how to use the package.


## How to contribute, provide feedback, or report bugs?

You can e-mail me at rafaelgfoster at gmail (.) com.

Enjoy it!

## JavaScript/TypeScript module

This repository also contains a Node.js client with the same controller and
method surface as the Python implementation. The compiled JavaScript is kept
in `dist/` so applications can install it directly from GitHub without a
public npm release.

Install the branch from GitHub:

```bash
npm install github:rafaelfoster/fortiedr#feat/typescript-client
```

Use it from JavaScript or TypeScript:

```js
import { auth, Inventory } from 'fortiedr';

const login = await auth('FORTIEDR_HOST.COM', 'USER', 'PASSWORD');
if (login.status) {
  const inventory = new Inventory();
  const collectors = await inventory.list_collectors();
  console.log(collectors);
}
```

For local development, run `npm install`, then `npm test`. `npm run build`
regenerates the controller manifest from the Python sources and compiles the
TypeScript client.
