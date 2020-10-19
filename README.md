# Description

GWTMap is a tool to help map the attack surface of Google Web Toolkit (GWT) based applications. The purpose of this tool is to facilitate the extraction of any service method endpoints buried within a modern GWT application's obfuscated client-side code, and attempt to generate example GWT-RPC requests payloads to interact with them.

More information can be found here: [https://labs.f-secure.com/blog/gwtmap-reverse-engineering-google-web-toolkit-applications](https://labs.f-secure.com/blog/gwtmap-reverse-engineering-google-web-toolkit-applications).

# Requirements

The script requires `Python3`, `argparse`, and `requests` to run. They can be installed using the following command: 
```
python -m pip install -r requirements.txt
```

# Usage 

## Help

```
$ ./gwtmap.py -h
usage: gwtmap.py [-h] [--version] -u <TARGET_URL> -F <FILE> [-b <BASE_URL>] [-p <PROXY>] [-c <COOKIES>] [-f <FILTER>] [--basic] [--rpc] [--probe] [--svc] [--code] [--backup [DIR]] [-q]

Enumerates GWT-RPC methods from {hex}.cache.js permutation files

Arguments:
  -h, --help            show this help message and exit
  --version             show program's version number and exit
  -u <TARGET_URL>, --url <TARGET_URL>
                        URL of the target GWT {name}.nocache.js bootstrap or {hex}.cache.js file
  -F <FILE>, --file <FILE>
                        path to the local copy of a {hex}.cache.js GWT permutation file
  -b <BASE_URL>, --base <BASE_URL>
                        specifies the base URL for a given permutation file in -F/--file mode
  -p <PROXY>, --proxy <PROXY>
                        URL for an optional HTTP proxy (e.g. -p http://127.0.0.1:8080)
  -c <COOKIES>, --cookies <COOKIES>
                        any cookies required to access the remote resource in -u/--url mode (e.g. 'JSESSIONID=ABCDEF; OTHER=XYZABC')
  -f <FILTER>, --filter <FILTER>
                        case-sensitive method filter for output (e.g. -f AuthSvc.checkSession)
  --basic               enables HTTP Basic authentication if require. Prompts for credentials
  --rpc                 attempts to generate a serialized RPC request for each method
  --probe               sends an HTTP probe request to test each method returned in --rpc mode
  --svc                 displays enumerated service information, in addition to methods
  --code                skips all and dumps the 're-formatted' state of the provided resource
  --backup [DIR]        creates a local backup of retrieved code in -u/--url mode
  -q, --quiet           enables quiet mode (minimal output)

Example: ./gwtmap.py -u "http://127.0.0.1/example/example.nocache.js" -p "http://127.0.0.1:8080" --rpc

```

## Usage

Enumerate the methods of a remote application via it's bootstrap file and create a local backup of the code (selects permutation at random ):
```
./gwtmap.py -u http://192.168.22.120/olympian/olympian.nocache.js --backup
```

Enumerate the methods of a remote application via a specific code permutation
```
./gwtmap.py -u http://192.168.22.120/olympian/C39AB19B83398A76A21E0CD04EC9B14C.cache.js
```

Enumerate the methods whilst routing traffic through an HTTP proxy:
```
./gwtmap.py -u http://192.168.22.120/olympian/olympian.nocache.js --backup -p http://127.0.0.1:8080
```

Enumerate the methods of a local copy (a file) of any given permutation:
```
./gwtmap.py -F test_data/olympian/C39AB19B83398A76A21E0CD04EC9B14C.cache.js
```

Filter output to a specific service or method: 
```
./gwtmap.py -u http://192.168.22.120/olympian/olympian.nocache.js --filter AuthenticationService.login
```

Generate RPC payloads for all methods of the filtered service
```
./gwtmap.py -u http://192.168.22.120/olympian/olympian.nocache.js --filter AuthenticationService --rpc
```

Automatically test (probe) the generate RPC request for the filtered service method
```
./gwtmap.py -u http://192.168.22.120/olympian/olympian.nocache.js --filter AuthenticationService.login --rpc --probe
```

# Complete Examples

Generate an RPC request for the method "testDetails", and automatically probe the service
```
$ ./gwtmap.py -u http://192.168.22.120/olympian/olympian.nocache.js --filter TestService.testDetails --rpc --probe   

   ___|  \        / __ __|   \  |     \      _ \
  |       \  \   /     |    |\/ |    _ \    |   |
  |   |    \  \ /      |    |   |   ___ \   ___/
 \____|    _/\_/      _|   _|  _| _/    _\ _|
                             version 0.1

[+] Analysing
====================
http://192.168.22.120/olympian/olympian.nocache.js
Permutation: http://192.168.22.120/olympian/4DE825BB25A8D7B3950D45A81EA7CD84.cache.js
+ fragment : http://192.168.22.120/olympian/deferredjs/4DE825BB25A8D7B3950D45A81EA7CD84/1.cache.js
+ fragment : http://192.168.22.120/olympian/deferredjs/4DE825BB25A8D7B3950D45A81EA7CD84/2.cache.js


[+] Module Info
====================
GWT Version: 2.9.0
Content-Type: text/x-gwt-rpc; charset=utf-8
X-GWT-Module-Base: http://192.168.22.120/olympian/
X-GWT-Permutation: 4DE825BB25A8D7B3950D45A81EA7CD84
RPC Version: 7
RPC Flags: 0


[+] Methods Found
====================

----- TestService -----

TestService.testDetails( java.lang.String/2004016611, java.lang.String/2004016611, I, D, java.lang.String/2004016611 )
POST /olympian/testService HTTP/1.1
Host: 192.168.22.120
Content-Type: text/x-gwt-rpc; charset=utf-8
X-GWT-Permutation: 4DE825BB25A8D7B3950D45A81EA7CD84
X-GWT-Module-Base: http://192.168.22.120/olympian/
Content-Length: 262

7|0|10|http://192.168.22.120/olympian/|67E3923F861223EE4967653A96E43846|com.ecorp.olympian.client.asyncService.TestService|testDetails|java.lang.String/2004016611|D|I|§param_Bob§|§param_Smith§|§param_"Im_a_test"§|1|2|3|4|5|5|5|7|6|5|8|9|§32§|§76.6§|10|

HTTP/1.1 200
//OK[1,["Name: param_Bob param_Smith\nAge: 32\nWeight: 76.6\nBio: param_\"Im_a_test\"\n"],0,7]


[+] Summary
====================
Showing 1/5 Services
Showing 1/25 Methods
```
