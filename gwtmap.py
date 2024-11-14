#!/usr/bin/python3

"""
GWTMap v0.1 BETA
Author: Oliver Simonnet @FSecureLabs

Released as open source by F-Secure Labs (c) 2020
under BSD 3-Clause License. See LICENSE for more.
"""

import re
import sys
import argparse
import random
import time
from getpass import getpass
from random import randint
from requests.auth import HTTPBasicAuth
import requests

VERSION = "0.1"

DESCRIPTON = "Enumerates GWT-RPC methods from {hex}.cache.js permutation files"

EXAMPLE = (
    f"Example: {sys.argv[0]} "
    '-u "http://127.0.0.1/example/example.nocache.js" '
    '-p "http://127.0.0.1:8080" --rpc'
)

BANNER = f"""
   ___|  \\        / __ __|   \\  |     \\      _ \\
  |       \\  \\   /     |    |\\/ |    _ \\    |   |
  |   |    \\  \\ /      |    |   |   ___ \\   ___/
 \\____|    _/\\_/      _|   _|  _| _/    _\\ _|"""

# Immutable global variables
F_SUFFIX = ".cache.js"
DEFERRED = "deferredjs/"
UNKNOWN = "Unknown"
BOOTSTRAP = "bootstrap"
PERMUTATION = "permutation"
FRAGMENT = "fragment"
CLEAN = "clean"
OBFCTD = "obfuscated"

# Global variables initialised at runtime
BASE_URL = "http://127.0.0.1/stub/"
GWT_PERMUTATION = UNKNOWN
GWT_VERSION = UNKNOWN
RPC_VERSION = UNKNOWN
RPC_FLAGS = UNKNOWN
RPC_MODE = False
CONTENT_TYPE = UNKNOWN
FILTER = "" # Output filter
COLOR_MODE = False

# Variables for HTTP operations
COOKIES = None
PROXIES = None
HTTP_USER = None
HTTP_PASS = None
HTTP_AUTH = None

# Common regex pattern for obfuscated variable
R_VAR = r"[a-zA-Z0-9_\.\$]+"

# Printing Formats
FORMAT = {
    "DEFAULT": "\033[0m",
    "HEADING": "\033[1m\033[1;34m",
    "ERROR": "\033[1m\033[31m",
    "WARNING": "\033[1m\033[1;33m",
    "BANNER": "\033[1m\033[31m",
}

# Java object types
COMPLEX_TYPES = {
    "STRING": "java.lang.String",
    "INTEGER": "java.lang.Integer",
    "DOUBLE": "java.lang.Double",
    "FLOAT": "java.lang.Float",
    "BYTE": "java.lang.Byte",
    "BOOLEAN": "java.lang.Boolean",
    "SHORT": "java.lang.Short",
    "CHAR": "java.lang.Char",
    "LONG": "java.lang.Long",
    "LIST": "java.util.List",
    "ARRAY": "java.util.ArrayList"
}

SIMPLE_TYPES = {
    "I": f"{COMPLEX_TYPES['INTEGER']}",
    "D": f"{COMPLEX_TYPES['DOUBLE']}",
    "F": f"{COMPLEX_TYPES['FLOAT']}",
    "B": f"{COMPLEX_TYPES['BYTE']}",
    "Z": f"{COMPLEX_TYPES['BOOLEAN']}",
    "S": f"{COMPLEX_TYPES['SHORT']}",
    "C": f"{COMPLEX_TYPES['CHAR']}",
    "J": f"{COMPLEX_TYPES['LONG']}"
}

##################################################
# Utilities
##################################################
def writer(text="", fmt=FORMAT['DEFAULT']):
    """ Prints formatted text """
    if fmt == FORMAT['DEFAULT'] or not COLOR_MODE:
        print(text)
    else:
        print(rf"{fmt}{text}{FORMAT['DEFAULT']}")

def print_heading(text):
    """ Prints the given text in a heading-type format """
    writer(f"\n[+] {text}\n{'=' * 20}", FORMAT['HEADING'])

def sort_by(dict_list, key):
    """ Returns a List of dictionaries, sorted by a specific key """
    return sorted(dict_list, key=lambda k: k[key])

def is_number(value):
    """ Returns True if the given string value is numeric """
    try:
        float(value)
        return True
    except ValueError:
        return False

##################################################
# Code for presenting the tool's final output
##################################################
def present_banner():
    """ Prints the script's banner art """
    writer(BANNER, FORMAT["BANNER"])
    writer(" " * 30 + f"version {VERSION}")

def present_target(target):
    """ Prints the target resource being analysed """
    print_heading("Analysing")
    writer(target)

def present_module_info():
    """ Prints the GWT information """
    writer()
    print_heading("Module Info")
    writer(f"GWT Version: {GWT_VERSION}")
    writer(f"Content-Type: {CONTENT_TYPE}")
    writer(f"X-GWT-Module-Base: {BASE_URL}")
    writer(f"X-GWT-Permutation: {GWT_PERMUTATION}")
    if RPC_MODE:
        writer(f"RPC Version: {RPC_VERSION}")
        writer(f"RPC Flags: {RPC_FLAGS}")
    writer()

def present_code(code):
    """ Prints the current state of the code """
    writer('\n'.join(code))
    sys.exit(0)

def present_services(services, quiet):
    """ Prints the enumerated GWT services """
    if not quiet:
        print_heading("Services Found")
    else:
        writer()

    if len(services) < 1:
        writer("No services were identified!", FORMAT['WARNING'])
    else:
        for service in services:
            writer(f"Policy Strong Name: {service['strongName']} - Path: {service['servicePath']}")
    writer()

def present_rpc_method(method, send_probe):
    """ Prints the method's RPC request structure """
    svc_path_bk = method["rmtSvcIntName"].split(".")[-1]
    if method["service"] is None:
        svc_path_bk = svc_path_bk[0].lower() + svc_path_bk[1:]
        writer(
            f"Warning: Unable to correlate method to a service path. Guessed /{svc_path_bk}\n"
            + " - Strong name unknown - Use --svc to see options",
            FORMAT['WARNING']
        )
    if RPC_VERSION != "7":
        writer(
            "Warning: RPC body generation may be invalid - version 7 expected"
            + f", version {RPC_VERSION} found",
            FORMAT['WARNING']
        )
    if len(method["complexTypes"]) != 0:
        writer(
            "Warning: Unhandled complex type found - RPC likely invalid:\n - {}"
            .format('\n - '.join(method['complexTypes'])),
            FORMAT['WARNING']
        )

    service_path = (
        method["service"]["servicePath"]
        if method["service"] is not None
        else svc_path_bk
    )
    rpc_call = '|'.join(method["methodRpcCall"]) + "|"

    writer(
        "POST /{}{} HTTP/1.1\r".format(
            '/'.join(BASE_URL.split("/")[3:]), service_path
        ).replace("//", "/")
    )
    writer(f"Host: {BASE_URL.split('/')[2]}\r")
    writer(f"Content-Type: {CONTENT_TYPE}\r")
    writer(f"X-GWT-Permutation: {GWT_PERMUTATION}\r")
    writer(f"X-GWT-Module-Base: {BASE_URL}\r")
    writer(f"Content-Length: {len(rpc_call.encode('utf-8'))}\r\n\r")
    writer(f"{rpc_call}\n")

    if send_probe:
        url = (BASE_URL + service_path)
        send_rpc_probe(url, rpc_call)

def send_rpc_probe(url, rpc_call):
    """ Sends a test HTTP POST request the specified method """
    headers = {
        "Content-Type" : CONTENT_TYPE,
        "X-GWT-Permutation": GWT_PERMUTATION,
        "X-GWT-Module-Base": BASE_URL,
    }
    try:
        response = requests.post(
            url, data=rpc_call.replace("§", ""),
            headers=headers, proxies=PROXIES, cookies=COOKIES, auth=HTTP_AUTH, verify=False
        )
        writer(f"HTTP/1.1 {response.status_code}")
        writer(f"{response.text}\n")

    except requests.exceptions.RequestException:
        writer(f"\nError: probe failed for {url}\n", FORMAT['ERROR'])

def present_methods(methods, quiet, send_probe):
    """ Prints the enumerated GWT methods """
    ret_service_count, ret_method_count = 0, 0
    if not quiet:
        print_heading("Methods Found")

    if len(methods) < 1:
        writer("No methods were identified!", FORMAT['WARNING'])
        return 0, 0

    service_category = ""
    for _, method in enumerate(methods):

        method_string = "{}.{}( {} )".format(
            method["serviceProxy"][:-6],
            method["methodName"], ', '.join(method["methodSignature"])
        ).replace("(  )", "()")

        if FILTER in method_string:
            if method["serviceProxy"] != service_category:
                writer(f"\n----- {method['serviceProxy'][:-6]} -----\n")
                ret_service_count += 1

            service_category = method["serviceProxy"]

            writer(method_string, FORMAT['HEADING'] if RPC_MODE else FORMAT['DEFAULT'])
            ret_method_count += 1

            if RPC_MODE:
                present_rpc_method(method, send_probe)

    if not RPC_MODE:
        writer()

    return ret_service_count, ret_method_count

def present_summary(services, methods, count, backup):
    """ Prints the target resource being analysed """
    print_heading("Summary")
    if backup is not None:
        writer(f"Backup: {backup}")
    writer(f"Showing {count[0]}/{len(services)} Services")
    writer(f"Showing {count[1]}/{len(methods)} Methods\n")

##################################################
# Methods for extracting values from static code
##################################################
def extract_permutations(code, code_type):
    """ Returns a List of code permutation values """
    if code_type.endswith(CLEAN):
        permutations, permutation_pattern = [], re.compile(
            r"unflattenKeylistIntoAnswers\(.*, ?'[A-Z0-9]{32}'\);"
        )
        for line in code:
            if permutation_pattern.search(line):
                permutations.append(re.findall(r"([A-Z0-9]{32})", line)[0])

            if len(permutations) >= 5:
                return permutations

    else:
        permutation_pattern = re.compile(r"='?\"?selectingPermutation'?\"?,")
        for line in code:
            if permutation_pattern.search(line):
                return re.findall(r"([A-Z0-9]{32})", line)

    return None

def is_fragmented(code, code_type):
    """ Returns True if the permutation file is fragmented """
    if code_type.endswith(CLEAN):
        code = ''.join(code.split("\n"))

    frag_calls = re.findall(r"__gwtStartLoadingFragment\(", code)
    return len(frag_calls) > 1

def find_value(code, value):
    """ Returns the value of a given variable name within the code """
    value_pattern = re.compile(rf"{re.escape(value)} ?= ?([^=][a-zA-Z0-9\.'/_)(]*)")

    target = None
    for line in code:
        if value_pattern.search(line):
            target = re.findall(value_pattern, line)
            break

    return target[0] if target is not None else value

def parse_parameter(code, param):
    """ Returns value of a given parameter, if not a litteral string """
    if (
        param != "null"
        and param[0] != "'"
        and not is_number(param)
    ):
        return find_value(code, param).replace("'", "")

    return param.replace("'", "")

def get_offset(code, line, key):
    """ Returns the offset between a given line number
        and the next line containing a specified key word"""
    offset = 0
    while True:
        if key in code[line + offset].replace(" ", ""):
            break
        offset += 1
    return offset

##################################################
# Code for building a method's RPC body structure
##################################################
def get_method_parameter_values(code, line, full_sig):
    """ Returns a List of parameter values for the method at a given line """
    param_list = []
    offset = int((get_offset(code, line, "catch(") - 3))
    line += (1 + int(offset / 2))

    for i in range(int(offset / 2)):
        param_pattern = re.compile(rf", ?(?:'' ?\+ ?)?(?:{R_VAR}\(?.*, ?)?(.*[^\)])\)\)?;")
        nested_boolean_pattern = re.compile(rf".*\?(('?{R_VAR}'?):('?{R_VAR}'?))")
        param = re.findall(param_pattern, code[line])[0].replace("'", "")

        # if parameter is boolean, append 0
        if (
            nested_boolean_pattern.search(code[line])
            or full_sig[i].startswith(COMPLEX_TYPES["BOOLEAN"])
        ):
            param_list.append("§0§")

        # if parameter is numeric, append directly
        elif is_number(param) or full_sig[i].startswith("I"):
            param_list.append(f"§{param if is_number(param) else randint(0,99)}§")

        # else, treat as tring and append with previx
        else:
            param = param.replace(" ", "_").replace("|", "\\!").replace("\\", "\\\\")
            param_list.append(f"§param_{param}§")
        line += 1

    return param_list

def normalise_signature(method_signature):
    """ Returns a normalized method signature, as a List """
    normalised = list(set(method_signature))

    # Specific logic for normalizing the script's custom java.util.List type format
    list_object_pattern = re.compile(
        r"(java\.util\.(?:[A-Za-z]+)?List(?:[0-9\/]+)?)<([a-zA-Z0-9\.\/]+)[<>]?(?:(.*[^>]))?>"
    )

    for i, sig in enumerate(normalised):
        # If list object found, fragment and append each part to the signature List
        if re.match(list_object_pattern, sig):
            parts = list(re.findall(list_object_pattern, sig)[0])

            for j, part in enumerate(parts):
                if j == 0:
                    normalised[i] = part
                else:
                    normalised.insert(i + j, part)

    # Filter duplicate and empty elements from the final signature
    return list(filter(None,list(set(normalised))))

def generate_parameter_map(rpc_blocks, full_signature, param_values):
    """ Returns the RPC parameter map for the given method, as a List """
    parameter_map = []
    list_object_pattern = re.compile(
        r"(java\.util\.(?:[A-Za-z]+)?List(?:[0-9/]+)?)<([a-zA-Z0-9./]+)[<>]?(?:(.*[^>]))?>"
    )

    # Append type index for each parameter value
    for i, param in enumerate(param_values):
        param_type = full_signature[i]

        # If parameter is of type list, append index of list type
        if re.match(list_object_pattern, param_type):
            list_type = re.findall(list_object_pattern, param_type)[0][0]
            parameter_map.append(str(rpc_blocks.index(list_type) - 2))

        # If not of type list, appeand index of simple type
        else:
            parameter_map.append(str(rpc_blocks.index(full_signature[i]) - 2))

    # For each indexed parameter append type and value indicies
    for i, param in enumerate(param_values):
        param_type = full_signature[i]

        # If parameter is a string object, append value index
        if param_type.startswith(COMPLEX_TYPES["STRING"]):
            parameter_map.append(str(rpc_blocks.index(param) - 2))

        # Else if the parameter is simple type, append value
        elif param_type in SIMPLE_TYPES.keys():
            parameter_map.append(str(param))

        # Else if the parameter is a java list object, append type index and length
        elif re.match(list_object_pattern, param_type):
            list_length = 1
            list_type = list(filter(None, re.findall(list_object_pattern, param_type)[0]))

            parameter_map.append(
                str(rpc_blocks.index(list_type[0] if len(list_type) < 3 else list_type[1]) - 2)
            )
            parameter_map.append(str(list_length))

            # For each element of the list, append type and value indicies
            for _ in range(list_length):
                parameter_map.append(
                    str(rpc_blocks.index(list_type[1] if len(list_type) < 3 else list_type[2]) - 2)
                )
                parameter_map.append(str(rpc_blocks.index(param) - 2))

        # If parameter is a so far unhandled complex type, append runtime index and value
        elif any(
            param_type.startswith(val)
            for val in COMPLEX_TYPES.values()
        ):
            parameter_map.append(str(rpc_blocks.index(param_type) - 2))
            parameter_map.append(str(param))

        # If parameter is unknown, append runtime index and value index
        else:
            parameter_map.append(str(rpc_blocks.index(param_type) - 2))
            parameter_map.append(str(rpc_blocks.index(param) - 2))

    return parameter_map

def get_string_values(param_values, full_signature):
    """ Returns a Tuple containing a List of 'string' parameter values and
        a List of complex types identified - to be treated as string values """
    strings, complex_types = [], []
    for i, value in enumerate(param_values):
        # If value is string, append value to strings List
        if COMPLEX_TYPES["STRING"] in full_signature[i]:
            strings.append(value)

        # Else if unknown type, append to complex types List
        elif (
            not any(
                full_signature[i].startswith(val)
                for val in COMPLEX_TYPES.values()
            )
            and full_signature[i] not in SIMPLE_TYPES.keys()
        ):
            complex_types.append(full_signature[i])
            strings.append(value)

    return strings, list(set(complex_types))

def build_method_call(code, line, method_object):
    """
    Returns a Tuple of Lists containing the GWT-RPC call structure and
    the list of complex types it contains, for the given method object

    Note: This is unfortunately not 100% reliable, and can only
    process and serialize a small number of known Java types
    """
    full_signature = method_object["methodSignature"]
    normalised_signature = normalise_signature(full_signature)
    param_values = get_method_parameter_values(code, line, full_signature)
    string_values, cmplx_types = get_string_values(param_values, full_signature)

    rpc_payload_length = str(
        4 + len(normalised_signature) + len(string_values)
    )
    # Default to stub value if method-to-service correlation failed
    strong_name = (
        method_object["service"]["strongName"]
        if method_object["service"] is not None
        else "X"*32
    )
    rpc_blocks = []
    rpc_blocks.extend([
        RPC_VERSION,
        RPC_FLAGS,
        rpc_payload_length,
        BASE_URL,
        strong_name,
        method_object["rmtSvcIntName"],
        method_object["methodName"],
    ])
    rpc_blocks.extend(normalised_signature)
    rpc_blocks.extend(string_values)
    rpc_blocks.extend([
        "1", "2", "3", "4",
        method_object["paramCount"]
    ])
    rpc_blocks.extend(
        generate_parameter_map(
            rpc_blocks,
            full_signature,
            param_values
        )
    )
    return rpc_blocks, cmplx_types

##################################################
# Enmerate methods within the static code
##################################################
def extract_method_signature(code, line):
    """ Returns a List of parameters for a given method """
    line += 5
    method_signature = []
    offset = get_offset(code, line, "catch(")
    param_pattern = re.compile(rf"{R_VAR}\(.*, ?.*, ?(.*)\)\);")

    for _ in range(int((offset - 2) / 2)):
        parameter = parse_parameter(code, re.findall(param_pattern, code[line])[0])
        if parameter in ["", None]:
            parameter = "UNKNOWN"
        
        # If List type found, assume ArrayList implementation of Strings
        if parameter.startswith(COMPLEX_TYPES["LIST"]):
            parameter += f"<{COMPLEX_TYPES['ARRAY']}/4159755760"
            parameter += f"<{COMPLEX_TYPES['STRING']}/2004016611>>"

        # If specific List implementation found, assume it is of Strings
        elif re.match(r"java\.util\.[A-Za-z]+List/.*", parameter):
            parameter += f"<{COMPLEX_TYPES['STRING']}/2004016611>"

        method_signature.append(parameter)

        line += 1

    return method_signature

def correlate_service(method, service_objects):
    """ Returns the service containing the appropriate service path
        for the provided method, if a match is found """
    service_segment = method["rmtSvcIntName"].lower().split(".")[-1]
    for service in service_objects:
        service_path = service["servicePath"].lower().replace("/", "")
        if (
            service_segment in service_path
            or service_path in service_segment
        ):
            return service

    return None

def extract_method_info(code, service_objects):
    """ Returns a List of enumerated GWT method objects """
    method_pattern = re.compile(
        rf"({R_VAR} ?= ?new\ ?{R_VAR}\({R_VAR}, ?)('?{R_VAR}'?), ?('?.*'?)\)\;"
    )
    method_objects, loc = [], 0
    for line in code:
        if method_pattern.search(line) and code[loc + 1].find("try") != -1:
            # If a method definition is found, break it into its values
            method = re.findall(method_pattern, line)

            # define two distinct patterns for obfuscated remote service interfaces
            rmt_svc_pattern_1 = re.compile(
                rf"^[ \t]*(?:{R_VAR} ?= ?)?{R_VAR}\({R_VAR}, ?(.*), ?(.*)\);"
            )
            rmt_svc_pattern_2 = re.compile(
                rf"{R_VAR} ?= ?\(.*\({R_VAR}, ?(.*)\).*, ?.*\(.*\).*, ?(.*)\), ?.*\);"
            )

            # Extract the remote service interface value for the identified method
            rmt_svc_int_name_value = re.findall(rmt_svc_pattern_1, code[loc + 2])
            if rmt_svc_int_name_value == []:
                rmt_svc_int_name_value = re.findall(rmt_svc_pattern_2, code[loc + 2])

            # Initialize the method object's key values
            method_object = {
                "methodName": parse_parameter(code, method[0][2]),
                "methodSignature": extract_method_signature(code, loc - 2),
                "serviceProxy": parse_parameter(code, method[0][1]),
                "rmtSvcIntName": parse_parameter(code, rmt_svc_int_name_value[0][0]),
                "paramCount": parse_parameter(code, rmt_svc_int_name_value[0][1]),
            }

            # If RPC mode enabled, correlate method with a service
            # and create its respective RPC request structure
            if RPC_MODE:
                service = correlate_service(method_object, service_objects)
                method_object["service"] = service

                rpc_call, ctypes = build_method_call(code, loc + 2, method_object)
                method_object["methodRpcCall"] = rpc_call
                method_object["complexTypes"] = ctypes

            method_objects.append(method_object)

        loc += 1

    return sort_by(method_objects, "serviceProxy")

##################################################
# Enmerate services within the static code
##################################################
def extract_service_info(code):
    """ Returns a List of enumerated GWT service objects """
    service_pattern = re.compile(
        rf"{R_VAR}\.call\(this, ?{R_VAR}\(\), ?(?:(.*), ?)?(.*), ?{R_VAR}\)"
    )

    service_objects, loc = [], 0
    for line in code:
        if service_pattern.search(line):
            service = re.findall(service_pattern, line)

            service_object = {
                "servicePath": parse_parameter(code, service[0][0])
                               if service[0][0] != "" else "Unknown",
                "strongName": parse_parameter(code, service[0][1]),
            }
            service_objects.append(service_object)

        loc += 1

    return sort_by(service_objects, "servicePath")

##################################################
# Initialize global variables
##################################################
def set_http_params(args):
    """ Initializes the global variables used for HTTP traffic """
    global HTTP_USER, HTTP_PASS, HTTP_AUTH
    global CONTENT_TYPE, PROXIES, COOKIES
    requests.packages.urllib3.disable_warnings()

    if args.proxy is not None:
        PROXIES = {args.proxy.split(":")[0].lower(): args.proxy}

    if args.cookies is not None:
        cookies_list = {}
        for cookie in args.cookies.split(";"):
            cookies_list[cookie.split("=")[0].strip()] = cookie.split("=")[1].strip()
        COOKIES = cookies_list

    CONTENT_TYPE = "text/x-gwt-rpc; charset=utf-8"

    if args.basic:
        print_heading("HTTP Basic Auth")
        HTTP_USER = input("Username: ")
        HTTP_PASS = getpass("Password: ")
        HTTP_AUTH = HTTPBasicAuth(HTTP_USER, HTTP_PASS)
        writer()

def set_base_url(url):
    """ Initializes the global URL value for the module """
    global BASE_URL
    if url is not None:
        BASE_URL = '/'.join((url.split("/")[:-1])) + "/"

def set_globals(code, args):
    """ Initialises the module's global variables """
    global BASE_URL, GWT_PERMUTATION, GWT_VERSION
    global RPC_VERSION, RPC_FLAGS, RPC_MODE, FILTER
    FILTER, RPC_MODE = args.filter, args.rpc

    strongname_pattern = re.compile(r"var \$strongName ?= ?'([A-Z0-9]{32})';")
    gwt_ver_pattern = re.compile(r"var \$gwt_version ?= ?\"([0-9.]+)\";")
    rpc_ver_pattern = re.compile(r"^(?:[\t ]*)_\.(?:(?:k)|(?:version)) ?= ?([5-7]);")
    rpc_flags_pattern = re.compile(rf"^(?:[\t ]*)?{R_VAR} ?= ?([0-2]);")

    # Search static code for the appropriate module values
    for i, line in enumerate(code):
        if GWT_VERSION == UNKNOWN and gwt_ver_pattern.search(line):
            GWT_VERSION = re.findall(gwt_ver_pattern, line)[0]

        if GWT_PERMUTATION == UNKNOWN and strongname_pattern.search(line):
            GWT_PERMUTATION = re.findall(strongname_pattern, line)[0]

        if RPC_VERSION == UNKNOWN and rpc_ver_pattern.search(line):
            RPC_VERSION = re.findall(rpc_ver_pattern, line)[0]
            RPC_FLAGS = re.findall(rpc_flags_pattern, code[i - 1])[0]

        # If all values found, break out of the code review
        if all(x != UNKNOWN for x in [GWT_PERMUTATION, GWT_VERSION, RPC_VERSION, RPC_FLAGS]):
            break

##################################################
# Format obfuscated code before analysis
##################################################
def retab(code):
    """ Returns the provided code List with updated tabbing """
    tabs, tabbed_code = 0, ""
    for line in code.split("\n"):
        if line.strip() == "}":
            tabs -= 1

        tabbed_code += tabs * "\t" + line + "\n"
        if line.strip().endswith("{"):
            tabs+=1

    return tabbed_code

def clean_code(code, code_type):
    """ Returns the provided code string as a List of lines """
    if code_type.startswith(BOOTSTRAP):
        if code_type.endswith(CLEAN):
            return code.split("\n")
        code = code.replace("\\", "\\\\")

    if code_type.startswith(PERMUTATION):
        if code_type.endswith(CLEAN):
            return code.split("\n")

    if code_type.startswith(FRAGMENT):
        if code_type.endswith(CLEAN):
            return bytes(code, encoding="ascii").decode('unicode_escape')

    code = code.replace("{", "{\\n").replace("}", "\\n}\\n").replace(";", ";\\n")
    code = retab(bytes(code, encoding="ascii").decode('unicode_escape'))
    return code.split("\n")

##################################################
# Validate provided resource
##################################################
def classify_response(response):
    """ Returns the type identifier for the provied source code """
    bootstrap_pattern_o = re.compile(r"^function .*\(\)\{.*=\"?'?bootstrap.*=\"?'?begin")
    bootstrap_pattern_c = re.compile(r"^function [a-zA-Z0-9_\.\$]+\(\)\{")

    permutation_pattern_o = re.compile(r"^[a-zA-Z0-9_\.\$]+\.onScriptDownloaded\(\[.*")
    permutation_pattern_c = re.compile(r"^var \$wnd = \$wnd \|\| window\.parent;")

    frag_pattern_o = re.compile(rf"^{R_VAR}\.runAsyncCallback.*")
    frag_pattern_c = re.compile(
        rf"^{R_VAR}\.runAsyncCallback[0-9]+\(['\"](?:(?:\$entry)|(?:defineClass))\("
    )

    if bool(bootstrap_pattern_o.match(response)):
        return f"{BOOTSTRAP}_{OBFCTD}"
    if bool(bootstrap_pattern_c.match(response)):
        return f"{BOOTSTRAP}_{CLEAN}"

    if bool(permutation_pattern_o.match(response)):
        return f"{PERMUTATION}_{OBFCTD}"
    if bool(permutation_pattern_c.match(response)):
        return f"{PERMUTATION}_{CLEAN}"

    if bool(frag_pattern_c.match(response)):
        return f"{FRAGMENT}_{CLEAN}"
    if bool(frag_pattern_o.match(response)):
        return f"{FRAGMENT}_{OBFCTD}"

    writer(
        f"{sys.argv[0]}: error: target resource seems invalid...\n"
        + "Target resource must be:\n"
        + " 1) Obfuscated {name}.nocache.js GWT bootstrap file\n"
        + " 2) Obfuscated {hex}.cache.js GWT permutation file\n"
        + " 3) Obfuscated {int}.cache.js GWT deferred fragment file"
    )
    sys.exit(1)

def check_warnings(code_type, args):
    """ Prints a warning if unreliable / unexpected use identified """
    if code_type.startswith(FRAGMENT) and args.file is not None and args.code is False:
        writer(
            "Warning: Analysing a deferred fragment in -F/--file "
            + "mode will most likely cause errors", FORMAT['WARNING']
        )
    if code_type.startswith(PERMUTATION) and args.file is not None and args.code is False:
        writer(
            "Warning: Individual permutation files in -F/--file "
            + "mode do not include deferred fragments", FORMAT['WARNING']
        )

def url_mode_checks(value):
    """ Throws an error if an invalid resource is provided --url mode """
    if not value.endswith(F_SUFFIX[1:]):
        raise argparse.ArgumentTypeError(
            "\nURL resource must be:\n"
            + " 1) Obfuscated {name}.nocache.js GWT bootstrap file\n"
            + " 2) Obfuscated {hex}.cache.js GWT permutation file\n"
            + " 3) Obfuscated {int}.cache.js GWT deferred fragment file"
        )
    return value

def file_mode_checks(value):
    """ Throws an error if an invalid file is provided --file mode """
    if not value.endswith(F_SUFFIX):
        raise argparse.ArgumentTypeError(
            "\nFile resource must be:\n"
            + " 1) Obfuscated {hex}.cache.js GWT permutation file"
        )
    return value

##################################################
# Retrieve target resource data
##################################################
def write_file(data, file_path):
    """ Writed the provided data to a given file path """
    try:
        with open(file_path, "w") as file_obj:
            file_obj.write(data)

    except OSError:
        writer(f"\nwarning: Unable to write backup file {file_path}\n", FORMAT["WARNING"])

def save_code(code, code_type, directory):
    """ Saves the current state of the code to disk """
    output_code = ''.join(code)
    if directory is None:
        directory = "./"

    out_name = f"{directory}/{str(int(time.time()))}_{GWT_PERMUTATION}{F_SUFFIX}"
    out_name = out_name.replace("//", "/")

    if not code_type.endswith(CLEAN):
        output_code = output_code.replace("\\","\\\\").replace("\t","")

    write_file(output_code, out_name)
    return out_name

def read_file(file_path):
    """ Returns the provided file contents, and source code type """
    try:
        with open(file_path, "r") as file_obj:
            data = file_obj.read()
            code_type = classify_response(data)
            return data, code_type

    except FileNotFoundError:
        writer(f"\nerror: Unable to read file {file_path}\n", FORMAT["ERROR"])
        sys.exit(1)

def http_request(url):
    """ Returns HTTP status code and respones body for the given URL """
    try:
        response = requests.get(url, proxies=PROXIES, cookies=COOKIES, auth=HTTP_AUTH, verify=False)
        return response.status_code, response.text

    except requests.exceptions.RequestException:
        writer(f"\nError: Connection failed for {url}\n", FORMAT['ERROR'])
        sys.exit(1)

def fetch_code(url):
    """ Returns the source code and type for the provided URL respurce """
    status, response = http_request(url)

    if status != 200:
        writer(
            f"\nError: HTTP status {status} returned, 200 expected\n - {url}\n",
            FORMAT["ERROR"]
        )
        sys.exit(1)

    code_type = classify_response(response)

    return response, code_type

def append_fragments(code, code_type, args):
    """ Returns a new code List with any enumerated deferred JS fragments appended """
    miss, frag = 0, 0
    while miss < 2:
        frag_url = f"{BASE_URL}{DEFERRED}{GWT_PERMUTATION}/{frag}{F_SUFFIX}"
        status, response = http_request(frag_url)

        if not response:
            miss += 1
        elif status == 200:
            if not args.code and not args.quiet:
                writer(f"+ fragment : {frag_url}")

            code_type = classify_response(response)
            code.extend(clean_code(response, code_type))
        else:
            miss += 1

        frag += 1

    return code

def get_permutation(code, code_type, args):
    """ Returns the code of the first enumerated browser permutation """
    global GWT_PERMUTATION
    GWT_PERMUTATION = random.choice(extract_permutations(code, code_type))
    target = f"{BASE_URL}{GWT_PERMUTATION}{F_SUFFIX}"

    if not args.code and not args.quiet:
        writer(f"Permutation: {target}")

    code, code_type = fetch_code(target)
    return clean_code(code, code_type)

##################################################
# Main
##################################################
def main():
    """ Main function to orchestrates the script """
    parser = argparse.ArgumentParser(description=DESCRIPTON, epilog=EXAMPLE)
    parser.add_argument(
        "--version", action="version", version="%(prog)s {}".format(VERSION)
    )
    parser.add_argument(
        "-u", "--url", metavar="<TARGET_URL>",
        required="-F" not in sys.argv and "--file" not in sys.argv,
        help="URL of the target GWT {name}.nocache.js bootstrap or {hex}.cache.js file",
        type=url_mode_checks
    )
    parser.add_argument(
        "-F", "--file", metavar="<FILE>", default=None,
        required="-u" not in sys.argv and "--url" not in sys.argv,
        help="path to the local copy of a {hex}.cache.js GWT permutation file",
        type=file_mode_checks
    )
    parser.add_argument(
        "-b", "--base", metavar="<BASE_URL>", default=BASE_URL,
        help="specifies the base URL for a given permutation file in -F/--file mode"
    )
    parser.add_argument(
        "-p", "--proxy", metavar="<PROXY>", default=None,
        help="URL for an optional HTTP proxy (e.g. -p http://127.0.0.1:8080)"
    )
    parser.add_argument(
        "-c", "--cookies", metavar="<COOKIES>", default=None,
        help="any cookies required to access the remote resource in -u/--url mode "
        + "(e.g. 'JSESSIONID=ABCDEF; OTHER=XYZABC')"
    )
    parser.add_argument(
        "-f", "--filter", metavar="<FILTER>", default="",
        help="case-sensitive method filter for output (e.g. -f AuthSvc.checkSession)"
    )
    parser.add_argument(
        "--basic", action="store_true", default=False,
        help="enables HTTP Basic authentication if require. Prompts for credentials"
    )
    parser.add_argument(
        "--rpc", action="store_true", default=False,
        required="--probe" in sys.argv,
        help="attempts to generate a serialized RPC request for each method"
    )
    parser.add_argument(
        "--probe", action="store_true", default=False,
        help="sends an HTTP probe request to test each method returned in --rpc mode"
    )
    parser.add_argument(
        "--svc", action="store_true", default=False,
        help="displays enumerated service information, in addition to methods"
    )
    parser.add_argument(
        "--code", action="store_true", default=False,
        help="skips all and dumps the 're-formatted' state of the provided resource"
    )
    parser.add_argument(
        "--color", action="store_true", default=False,
        help="enables coloured console output"
    )
    parser.add_argument(
        "--backup", metavar="DIR", nargs='?', default=False,
        help="creates a local backup of retrieved code in -u/--url mode"
    )
    parser.add_argument(
        "-q", "--quiet", action="store_true", default=False,
        help="enables quiet mode (minimal output)"
    )

    parser._optionals.title = "Arguments"
    args = parser.parse_args()

    global COLOR_MODE
    COLOR_MODE = args.color

    if not args.code and not args.quiet:
        present_banner()

    set_base_url(args.url if args.base is BASE_URL else args.base)

    set_http_params(args)

    if not args.code and not args.quiet:
        present_target(args.url if args.file is None else args.file)

    code, code_type = (
        read_file(args.file) if args.file is not None else
        fetch_code(args.url)
    )

    check_warnings(code_type, args)

    code = clean_code(code, code_type)

    if code_type.startswith(BOOTSTRAP) and args.file is None:
        code = get_permutation(code, code_type, args)

    set_globals(code, args)

    if is_fragmented(''.join(code), code_type) and args.file is None:
        code = append_fragments(code, code_type, args)

    backup_file = None
    if args.backup is not False and args.file is None:
        backup_file = save_code(code, code_type, args.backup)

    if args.code:
        present_code(code)
        sys.exit(0)

    if not args.quiet:
        present_module_info()

    service_objects = extract_service_info(code)
    if args.svc:
        present_services(service_objects, args.quiet)

    method_objects = extract_method_info(code, service_objects)
    count = present_methods(method_objects, args.quiet, args.probe)

    if not args.quiet:
        present_summary(service_objects, method_objects, count, backup_file)

if __name__ == "__main__":
    main()
