# FortiEDR_API
A tool to provide an easy customizable foundation in order to create and consume FortiEDR APIs.

## How do I install FortiEDR_API?

Be sure you have at least Python 3.8 and PIP (https://pypi.org/project/pip/) installed.

After downloading this tool, use pip for installing dependencies using the following command:

`pip3 install -r requirements.txt`

## First steps with FortiEDR_API?

First of all, create an Rest API user on FortiEDR Management console:
 * Create an user with Rest API permissions on FortiEDR Console. You can check this doc for help: https://docs.fortinet.com/document/fortiedr/5.2.1/administration-guide/776468/users
 * After creating the user, this newly created user must log in to the Central Manager console and change their initial password before they can be used by Rest API calls.

 * Then go to **/config** folder and rename the **credentials.ini.default** to **credentials.ini**.
 * Define user, pass and host parameters as explained.
 * If you are working under a Multi-Tenancy environment, note that the parameter 'org' should be defined, otherwise you will get an HTTP 401 0 Unauthorized Access error


## How do I use FortiEDR_API?

After credentials being defined, you are now able to start consuming FortiEDR API.

The "main.py" file should contain all your standard code, while files in **/lib** folder will only contain functions to get/insert/update data with the API Gateway.

You can check [/lib/fortiedr_collectors.py](lib/fortiedr_collectors.py) so you can see some functions and have examples of how to build it.



## How to contribute, provide feedback or reporting bugs?

You can e-mail me at fosterr at fortinet (.) com.

Enjoy it!
