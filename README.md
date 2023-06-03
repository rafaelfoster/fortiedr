# FortiEDR_API
An Open-source python package intended to help on interacting with FortiEDR API.

## How do I install FortiEDR_API?

Be sure you have at least Python 3.10 and PIP (https://pypi.org/project/pip/) installed.

After downloading this tool, use pip for installing dependencies using the following command:

```
git clone https://github.com/rafaelfoster/FortiEDR_API.git

cd FortiEDR_API

pip3 install .
```

## First steps with FortiEDR_API

First of all, create a Rest API user on FortiEDR Management console:
 * Create a user with Rest API permissions on FortiEDR Console. You can check this doc for help: https://docs.fortinet.com/document/fortiedr/5.2.1/administration-guide/776468/users

 * After creating the user, this newly created user must log in to the Central Manager console and change their initial password before they can be used by Rest API calls.

After creating a user with privileges for interacting with FortiEDR API, you can start using the package by importing the modules you want to your code:

`from fortiedr import Auth, Policies`

Or you can import all the modules, by running:

`import fortiedr`

*Obs.: Auth module is mandatory for being able to authenticate with FortiEDR Management Host *

Once imported, you need to authenticate with Management Host using valid credentials, as such:

```
organization = "ORGANIZATION_NAME"

authentication = fortiedr.auth(
    user="USER",
    passw="PASSWORD",
    host="FORTIEDR_HOST.COM", # use only the hostname, without 'https://' and '/'.
    org=organization          # Add organization IF needed. Case sensitive
)
```

If the authentication is successful, you can proceed by interacting with the API.

## How do I use FortiEDR_API?

After credentials are defined and successfully authenticated, you are now able to start consuming FortiEDR API.

The "example.py" file contains some examples of how to use the package.


## How to contribute, provide feedback, or report bugs?

You can e-mail me at fosterr at fortinet (.) com.

Enjoy it!
