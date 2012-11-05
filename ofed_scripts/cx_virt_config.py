#!/usr/bin/env python
# -*- python -*-
#
# Author:  Sharon Cohen   sharonc@mellanox.co.il --  Created: 2011/Jan/01

import os
import sys
from copy import deepcopy

# Constant Values
APP_NAME                = "cx_virt_config"
UNASSIGNED_PKEY         = "0x0000"
INVALID_PKEY            = "none"
DELETE_GUID_VALUE       = "0xFFFFFFFFFFFFFFFF"
SM_ASSIGN_GUID_VALUE    = "0x0000000000000000"
EMPTY_GUID_VALUE        = '0x0000000000000000'
DEFAULT_VIRT_GUID_IDX   = "0"
MAX_TABLE_SIZE          = 126 # 0..126
TOOL_PARAMS             = { }

# some of the parameters that were given has to convert to list
PARAM_CONVERT_LIST      = ["add-pkey", "add-pkey-idx", "del-pkey", "del-pkey-idx"]
PKEY_OPERATION_LIST     = ["add-pkey", "add-pkey-idx", "del-pkey", "del-pkey-idx"]

# General Pathes
INFINIBAND_PATH         = "/sys/class/infiniband/"
IOV_PATH                = INFINIBAND_PATH  + "<mlx_device>/iov/"
REAL_TABLE_PATH         = IOV_PATH         + "ports/<port>/"
VIRTUAL_LUT_PATH        = IOV_PATH         + "<pci_device>/ports/<port>/"
# P KEY
REAL_PKEY_TABLE_PATH    = REAL_TABLE_PATH  + "pkeys/"
VIRTUAL_P_KEY_LUT_PATH  = VIRTUAL_LUT_PATH + "pkey_idx/"
# GUID
REAL_GUID_TABLE_PATH    = REAL_TABLE_PATH  + "gids/"
VIRTUAL_GUID_LUT_PATH   = VIRTUAL_LUT_PATH + "gid_idx/"
ALIAS_GUID_PATH         = REAL_TABLE_PATH  + "admin_guids/"
# MGID
MGID_TABLE_PATH         = REAL_TABLE_PATH  + "mcgs/"

# These tables will be filled at the 1st time and won't be updated, 
# Used for maximum performance.
REAL_TABLE_VALUE_DIC    = {}
VIRTUAL_TABLE_VALUE_DIC = {}
REAL_TABLE_INDEX_DIC    = {}
VIRTUAL_TABLE_INDEX_DIC = {}


###################################################################################
###################################################################################
###################################################################################

###################################################################################
################################ DEBUG TRACE  #####################################
###################################################################################

try:
	VL_TRACE = eval(os.environ['VL_TRACE'])
except Exception, e:
	VL_TRACE = 0

DataTraceFlag    = 1 << 1
MiscTraceFlag    = 1 << 2


################################# Print Functions #################################
######################################################################
# Function Name: ColorPrint.
# Arguments :	1- Color Text ['RED', 'GREEN', 'BRIGHT_RED',.....
# 		2- String to be printed
# Action: Print the given string with the given color (Work only on linux)
# Return Value: None
#######################################################################
def ColorPrint(Color, str):
	Colors = {
		"RED":'\033[31m',
		"GREEN":'\033[32m',
		"BROWN":'\033[33m',
		"BRIGHT_RED":'\033[91m',
		"BLUE":'\033[34m',
		"MAGENTA":'\033[35m',
		"CYAN":'\033[36m',
		"WHITE":'\033[37m',
		"BLACK":'\033[39m',
		"RESET":'\033[0;0m',
		"BOLD":'\033[1m',
		"ITALICS":'\033[3m',
		"UNDERLINE":'\033[4m'
		}

	if (Color not in Colors.keys()):
		TmpColor = "BLACK"
	else:
		TmpColor = Color
	if (not sys.stdout.isatty()):
		print str
		return

	print "%s%s%s" % (Colors[TmpColor], str, Colors["RESET"])
	return

######################################################################
# Function Name: PRINT_MSG.
# Arguments :
# 		1- String to be printed
# 		2- color (Default Black).
# 		3- cause (Default "").
# 		4- Stack Depth (Default 1).
# Action: Print the given message according to given color and cause
# Return Value: None
#######################################################################
def PRINT_MSG(str, color = "Black", cause = "", stack_depth=1):
	line		= sys._getframe(stack_depth).f_lineno
	file		= sys._getframe(stack_depth).f_code.co_filename
	func		= sys._getframe(stack_depth).f_code.co_name
	if func == "?":
		func = "Main"
	file = file.split(os.sep)[-1]
	ColorPrint(color, "%s , %4d [%-20s] %s: %s" % (file, line, func, cause, str) )

######################################################################
# Function Name: ERROR.
# Arguments :	1- String to be printed
# 		2- Stack Depth (Default 1).
# Action: TRACE the given string with ERR color(RED)
# Return Value: None
#######################################################################
def ERROR (str,stack_depth=1):
	PRINT_MSG(str, "RED", "ERROR", (stack_depth + 1))

######################################################################
# Function Name: EXCEPTION.
# Arguments :	1- String to be printed
# 		2- Stack Depth (Default 1).
# Action: TRACE the given string with ERR color(RED)
# Return Value: None
#######################################################################
def EXCEPTION (str,stack_depth=1):
	PRINT_MSG(str, "RED", "EXCEPTION", (stack_depth + 1))

######################################################################
# Function Name: DATA_WARNING.
# Arguments :	1- String to be printed
# 		2- Stack Depth (Default 1).
# Action: TRACE the given string with ERR color(RED)
# Return Value: None
#######################################################################
def WARNING (str,stack_depth=1):
	PRINT_MSG(str, "BRIGHT_RED", "WARNING", (stack_depth + 1))


######################################################################
# Function Name: DATA_TRACE.
# Arguments :	1- String to be printed
# 		2- Stack Depth (Default 1).
# Action: TRACE the given string with CYAN color
# Return Value: None
#######################################################################
def DATA_TRACE (str,stack_depth=1):
	PRINT_MSG(str, "BROWN", "DATA_TRACE", (stack_depth + 1))

######################################################################
# Function Name: DATA_OK.
# Arguments :	1- String to be printed
# 		2- Stack Depth (Default 1).
# Action: TRACE the given string with CYAN color
# Return Value: None
#######################################################################
def DATA_OK (str,stack_depth=1):
	PRINT_MSG(str, "GREEN", "", (stack_depth + 1))

######################################################################
# Function Name: MISC_TRACE.
# Arguments :	1- String to be printed
# 		2- Stack Depth (Default 1).
# Action: TRACE the given string with CYAN color
# Return Value: None
#######################################################################
def MISC_TRACE (str,stack_depth=1):
	PRINT_MSG(str, "CYAN", "MISC_TRACE", (stack_depth + 1))

######################################################################
# Function Name: DEBUG_TRACE.
# Arguments :	1- String to be printed
# 		2- Stack Depth (Default 1).
# Action: TRACE the given string with CYAN color
# Return Value: None
#######################################################################
def DEBUG_TRACE (str,stack_depth=1):
	if DataTraceFlag & VL_TRACE:
		PRINT_MSG(str, "MAGENTA", "DEBUG_TRACE", (stack_depth + 1))


###################################################################################
################################## COMMON  ########################################
###################################################################################

# Constant Command
XEN_IF_COMMAND          = "xm "
MACHINE_LIST            = "list"
ASSIGNABLE_PCI_LIST     = "pci-list-assignable-devices "
DESTROY_COMMAND         = XEN_IF_COMMAND + "des <guest_id>"
CREATE_COMMAND          = XEN_IF_COMMAND + "create <file_name>"
ATTACH_PCI_DEV_COMMAND  = " pci=<pci_bus>"

# Constant Variable
INFINIBAND_PATH        = "/sys/class/infiniband/"
MLX_DEVICE_PATH        = INFINIBAND_PATH + "<mlx_device>/iov/"
PORT_PATH        = "/sys/class/infiniband/<mlx_device>/iov/ports/"

###########################################################################
# Function: _is_xen_os
# return 0 if we are in Xen OS, 1 - not xen
# return value: 0 - Xen OS, 1 - Other OS, -1 - failure
###########################################################################
def is_xen_os():
    rc = 0

    DEBUG_TRACE("Starting _is_xen_os")
    cmd = "uname -r"
    (rc, output) = run_command(cmd)
    if rc:
        ERROR("Failed to run_command(%s)" % cmd)
        return -1

    DEBUG_TRACE("output %s" % str(output))
    if output.find("xen") != -1:
        return 1
    return 0


###########################################################################
# Function: is_opensm_down
#       return 0 if opensm is up.
# return value: 
#       0 - opensm up, 1-255 - opensm down\not responding
###########################################################################
def is_opensm_down():
    cmd = "sminfo"
    (rc, output) = run_command(cmd, False)
    return rc


###########################################################################
# Function: get_device_list
# return value: 
#       (0, mlx_device_list) - for success, (1, []) - failure
###########################################################################
def get_device_list():
    mlx_device_list = []

    cmd = "ls " + INFINIBAND_PATH
    (rc,output) = run_command(cmd)
    if rc:
        return (rc, mlx_device_list)

    output = output.replace("\n"," ")
    output = output.split(" ")
    for dev in output:
        if dev != '':
            mlx_device_list.append(dev)
    return (rc, mlx_device_list)


###########################################################################
# Function: get_dom0_device_according_to_pci_device
# return value: 
#       mlx_device - for success, None - failure
###########################################################################
def get_dom0_device_according_to_pci_device(pci_device):
    (rc, mlx_device_list) = get_device_list()
    if rc:
        ERROR("Failed to get mlx device list")
        return (rc, mlx_device)

    DEBUG_TRACE("mlx_device_list %s" % str(mlx_device_list))
    for mlx_device in mlx_device_list:
        DEVICE_PARAMS = {
                    "<mlx_device>"  : mlx_device,
        }
        cmd = "ls " + build_path(MLX_DEVICE_PATH, DEVICE_PARAMS)
        (rc,output) = run_command(cmd)
        if rc:
            return None
        if output.find(pci_device) != -1:
            return mlx_device # Found the relevant device, let's return it
    ERROR("the relevant mlx device for pci device %s was not found" % pci_device)
    return None


###########################################################################
# Function: get_dom0_pci_device
# return value: pci_device - for success, None - failure
###########################################################################
def get_dom0_pci_device():
    pci_device = None
    cmd = "lspci |grep \"Mellanox Technologies MT\""
    (rc, output) = run_command(cmd)
    if rc:
        return pci_device

    pci_device = "0000:" + output.split(' ')[0]
    return pci_device


###########################################################################
# Function: get_port_list
#       find and return all ports for a specific device.
#       Can also be activated by giving pci_device
# return value: 
#       port_list - for success, [] - failure
###########################################################################
def get_port_list(mlx_device = None, pci_device = None):
    port_list = []

    if mlx_device == None:
        mlx_device = get_dom0_device_according_to_pci_device(pci_device)
        if mlx_device == None:
            ERROR("Failed to get mlx device")
            return []

    cmd = "ls " + build_path(PORT_PATH, { "<mlx_device>" : mlx_device })
    (rc, output) = run_command(cmd)
    if rc:
        return port_list

    output = output.split("\n")
    for port in output:
        if port != "":
            port_list.append(port)
    return port_list

##################################################################
# Function: run_command
# return value: (0, output) - success, (1, output) - failed
##################################################################
def run_command (cmd, print_output_if_fail = True):
	DEBUG_TRACE("starting run_command %s" % (str(cmd)))

	try:
		fd = os.popen(cmd)
		output = fd.read()
		rc = fd.close()
	except Exception, e:
		EXCEPTION("Failed (%s), cmd %s" % (str(e), str(cmd)))
		return (1, None)

	if rc and print_output_if_fail:
		ERROR("%s Command output %s" % ("^" * 10, "^" * 10))
		ERROR("Failed to run %s" % cmd)
		ERROR(str(output))
		ERROR("rc = %s" % str(rc))
		ERROR("%s" % ("^" * 36))

	if (rc != None):
		rc = 1
	else:
		rc = 0

	return (rc, output)


##########################################################################
# Function :build_path
#   this is a generic function for building paths that "takes arguments",
#   i.e port and hca in a the following sysfs path - 
#       /sys/class/infiniband/mlx4_0/ports/1/counters/
# Example:
#   input - path_variable :
#           "/sys/class/infiniband/<mlx_device>/ports/<ib_port>/counters/"
#           args :
#           {"<mlx_device>":"mlx4_0", "<ib_port>":"1"}
#   output - /sys/class/infiniband/mlx4_0/ports/1/counters/
# Meaning - 
#   args  - is a dictionary which has a variable token as a key and it's value
#   as a value
#   path_variable - is a path with variable tokens
##########################################################################
def build_path(path_variable, args):
    try:
        for (token,value) in args.iteritems():
            path_variable = path_variable.replace(token, value)
    except Exception, e:
        EXCEPTION("Failed to build path %s (%s)" % (path_variable, str(e)))
        return None
    return path_variable



###################################################################################
############################### COMMAND LINE  #####################################
###################################################################################

######################################################################################################
#										Default Values												 #
######################################################################################################

# key / value indexes 
KEY_IDX		= 0
VALUE_IDX	= 1

######################################################################################################
#										Data Structures Template									 #
######################################################################################################

# hold definition of  parameters 
__params_definition_template	 	=	 {
											"app_name"				: "",
											"flags" 			: [], 
											"parameters" 		: [], 
											"collections" 		: [],
											"numeric_list" 		: [],
											"mandatory_params" 	: [],
											# default parameters [[key_1, value_1], [key_2, value_2], ... , [key_n, value_n]]
											"default_params"	: [],
											# hold valid options values of each parameter
											# [[param_1, [val_1, val_2 ... val_n], [param_2, [val_1, val_2, val_3 ... val_n]]
											"specific_values"	: [],
											# arguments to prints [_name, arg_1, arg_2, ... , arg_n]
											# arg_1 ... arg_n will print on insert order
											"print_list"		: []
										 }

# hold usage parameters and his descriptions
__usage_params_template 			=	 {
											"app_name"				: "",
											# mandatory parameters [[key_1, value_1], [key_2, value_2], ... , [key_n, value_n]]
											"mandatory_params"		: [],
											# optional parameters [[key_1, value_1], [key_2, value_2], ... , [key_n, value_n]]
											"optional_params"		: [],
											# examples command [[example_type_1 list], [example_type_2 list], ... , [example_type_n, list]
											# [["example_1, example_2, ... , example_n],  [example_1, example_2, ... , example_n], ... ]
											"example_cmd"			: []
										 }

# hold example types indexs (columns) each index represent list of example type 
__example_col_template 				= 	 {}

######################################################################################################
#										Data Structures												 #
######################################################################################################
# will initialization with clean database function
__params_definition		 = {}
__usage_params			 = {}
__example_col			 = {}

######################################################################################################
#								User Interface - Public Functions									 #
######################################################################################################

##########################################################################
# Function : add_flag
# Description : add flag parameter (e.g. --daemon)
# Return value : None
##########################################################################
def add_flag(name, description, print_param = True):
	# add parameter to data structures
	__add_param(name, description, "flags", is_mandatory = False, is_numeric = False, default_value = None, print_param = print_param, specific_values = [])

##########################################################################
# Function : add_parameter
# Description : add parameter on "key=value" format (e.g. --local_ip=10.3.3.200)
# Return value : None
##########################################################################
def add_parameter(name, description, is_mandatory = False, is_numeric = False, default_value = None, print_param = True, specific_values = []):
	# add parameter to data structures
	__add_param(name, description, "parameters", is_mandatory, is_numeric, default_value, print_param, specific_values)

##########################################################################
# Function : add_collection
# Description : add  collection parameter on "key=value" format
# (e.g. --ip_list="['11.3.3.200', '12.3.3.200']")
# Return value : None
##########################################################################
def add_collection(name, description, is_mandatory = False, default_value = None, print_param = True, specific_values = []):
	# add parameter to data structures
	__add_param(name, description, "collections", is_mandatory, is_numeric = False, default_value = default_value, print_param = print_param, specific_values = specific_values)

##########################################################################
# Function :add_example_command
# Description : add example of (client / daemon) command via daemon flag 
# Return value : None
##########################################################################
def add_example_command(example_command, category_type):
	global __usage_params, __example_col

	# example type index command
	example_idx = __example_col.setdefault(category_type, len(__example_col))

	if len(__usage_params["example_cmd"]) < example_idx + 1:
		__usage_params["example_cmd"].append([])

	# add example command to __usage_params data structure
	__usage_params["example_cmd"][example_idx].append(example_command)

##########################################################################
# Function : add_name
# Description : add  name to data structures
# Return value : None
##########################################################################
def add_name(_name):
	global __usage_params, __params_definition

	## add name to data structures
	__params_definition["app_name"] = _name
	__usage_params["app_name"] = __params_definition["app_name"]

	# add name to be the first item of print_list
	__params_definition["print_list"].insert(0, "app_name")

##########################################################################
# Function : init_params
# Description: initialization  params and handle his parameters
#	1. initialization _params with user arguments
#	2. initialization _params with default arguments (arguments with default values that the user doesn't supply)
#	3. validate that all mandatory parameters exist
# 	4. convert all string numeric values to int
#	5. print  details
# Return value : 0 success, 1 failed
##########################################################################
def init_params(arguments, _params = {}, exit_on_failed = True):
	# parse arguments and init  params
	rc = __parse_arguments(arguments, __params_definition, _params)

	if not rc:
		# completion default parameters - (none supply parameters) 
		__complete_default_values(_params, __params_definition["flags"], __params_definition["default_params"])

	# validate arguments - validate all mandatory parameters exist
	rc = rc or __validate_params(_params, __params_definition["mandatory_params"])

	# convert numeric string to integers (only numbers On string format (Not random!!!)) 
	rc = rc or __convert_numeric_string_to_int(_params, __params_definition["numeric_list"])

	# validate value params (specific values)
	rc = rc or __validate_value_params(_params, __params_definition["specific_values"])

	# print  details
	if (not rc) and (_params["short-output"] != True):
		__print__details(_params, __params_definition["print_list"])

	# exit on failed status when exit_on_failed flag is up
	if rc and exit_on_failed:
		sys.exit(rc)

	return rc

##########################################################################
# Function : clean_database
# Description : clean the database
# Return value : None
##########################################################################
def clean_database():
	global __params_definition, __usage_params, __example_col

	__params_definition	= deepcopy(__params_definition_template)
	__usage_params				= deepcopy(__usage_params_template)
	__example_col				= deepcopy(__example_col_template )

######################################################################################################
#										Private Functions											 #
######################################################################################################

##########################################################################
# Function : __add_param
# Description : add parameter to data structures
# Return value : None
##########################################################################
def __add_param(name, description, type_param, is_mandatory = False, is_numeric = False, default_value = None, print_param = True, specific_values = []):
	global __params_definition

	# add param to type_param list (flags, parameters, collections)
	__params_definition[type_param].append(name)

	# add param to mandatory list (parameters that will be validate exist) 
	if is_mandatory:
		__params_definition["mandatory_params"].append(name)

	# add param to numeric list (parameters that will be convert to integers)
	if is_numeric:
		__params_definition["numeric_list"].append(name)

	# add param to default_params (parameters with default values)
	if default_value != None:
		__params_definition["default_params"].append([name, default_value])
		description += " (default %s)" % str(default_value)

	# add specific values list
	if specific_values != []:
		__params_definition["specific_values"].append([name, specific_values])

	# add param to print list (parameters will be print in insert order except _name)
	if print_param:
		__params_definition["print_list"].append(name)

	# add param description to usage params data structure
	__add_description(name, description, type_param == "flags", is_mandatory)

##########################################################################
# Function : __add_description
# Description : add description to usage params data structure
# Return value : None
##########################################################################
def __add_description(name, description, is_flag = False, is_mandatory = False):
	global __usage_params

	# type param list (mandatory_params / optional_params)
	type_param = ("optional_params", "mandatory_params")[is_mandatory == True]

	# command description
	command_desc 	= "--" + str(name)

	# on none flags parameter - extend "--command_desc" to be "--command_desc=COMMAND_DESC"
	# (e.g. --local_ip  to be --local_ip=LOCAL_IP)
	if is_flag == False:
		command_desc += "=" + str(name).upper() 

	# add description to usage params data structure
	__usage_params[type_param].append([command_desc, description])

##########################################################################
# Function :__parse_arguments
# Description : parsing the arguments and fill  params
# Return value : 0 success, 1 failed
##########################################################################
def __parse_arguments(arguments, _params_definition = __params_definition, _params = {}):
	# display  usage
	if '--help' in arguments:
		__usage(__usage_params)
		sys.exit(0)

	# parse arguments
	while len(arguments) > 1:
		current_param = arguments[1].replace("--","").split('=')
		# update arguments on "--key=value" format (e.g. --local_ip=10.3.3.200)
		if len(current_param) > 1:
			# collection parameters
			if current_param[KEY_IDX] in _params_definition["collections"]:
				try:
					_params[current_param[KEY_IDX]] = eval(str(current_param[VALUE_IDX]).strip('"'))
				except Exception, e:
					EXCEPTION("Failed to run eval (%s)" % str(e))
					__usage(__usage_params)
					return 1

			# none collection parameters
			elif current_param[KEY_IDX] in _params_definition["parameters"]:
				_params[current_param[KEY_IDX]] = current_param[VALUE_IDX]

			# error inserting parameters
			else:
				ERROR("Bad parameter: %s is not valid" % current_param[KEY_IDX])
				__usage(__usage_params)
				return 1

		# update flags parameters (set True value)
		elif current_param[KEY_IDX] in _params_definition["flags"]:
			_params[current_param[KEY_IDX]] = True

		# error inserting parameters
		else:
			ERROR("Bad parameter: %s is not valid" % current_param[KEY_IDX])
			__usage(__usage_params)
			return 1

		arguments = arguments[1:]

	# set  name
	_params["app_name"] = __params_definition["app_name"]

	return 0

##########################################################################
# Function : __validate_params
# Description: check that all mandatory parameters exist
# Return value : 0 success, 1 failed
##########################################################################
def __validate_params(_params , mandatory_params = []):
	# check that all mandatory parameters exist
	for parameter in mandatory_params:
		if _params.has_key(parameter) == False:
			ERROR("Mandatory parameter %s is missing" % str(parameter))
			return 1

	return 0

##########################################################################
# Function : __validate_params_value
# Description: 
# Return value : 0 success, 1 failed
##########################################################################
def __validate_value_params(_params, specific_values = []):
	for param in specific_values:
		if _params.get(param[0]) and _params.get(param[0]) not in param[1]:
			ERROR("Illegal \"%s\" parameter value \"%s\"" % (str(param[0]), str(_params.get(param[0]))))
			ERROR("\"%s\" valid values (%s)" % (str(param[0]), str(param[1])[1:-1]))
			return 1

	return 0

##########################################################################
# Function : __complete_default_values
# Description:  complete none supplied parameters with default values, 
# 				(flags (False value) and  parameter (His default value)) 
# Return value : None
##########################################################################
def __complete_default_values(_params, flags = [], default_params = []):
	# add flag with False value to all none using flags
	for flag in flags:
		_params.setdefault(flag, False)

	# add default values to all not supplied params 
	for param in default_params:
		_params.setdefault(param[KEY_IDX], param[VALUE_IDX]) 

##########################################################################
# Function : __convert_numeric_string_to_int
# Description: convert numeric string to integers and set it into _params
# Return value : 0 success, 1 failed
##########################################################################
def __convert_numeric_string_to_int(_params, numeric_list):
	# convert all numeric string parameters to int and set it into  params
	for numeric_param in numeric_list:
		try:
			_params[numeric_param] = int(_params[numeric_param])

		except Exception, e:
			EXCEPTION("Failed to convert to int (%s)" % str(e))
			return 1

	return 0

##########################################################################
# Function : __print__details
# Description : print the  details via _params values in insert order except
# _name (will be first item to print)
# Return value : None
##########################################################################
def __print__details(_params, print_list = []):
	if print_list == []:
		return 

	# print top title
	print "\n" + "#" * 75

	# print required parameters
	for param in print_list:
		if (_params.get(param, "") != "") and (_params.get(param, "") != False):
			print "%-30s : %s" % (" ".join(param.split('_')), _params.get(param, ""))

	# print bottom title
	print "#" * 75 + "\n"

##########################################################################
# Function : __usage
# Description : print commands guide of the 
# Return value : None
##########################################################################
def __usage(usage_params = {}):
	# print top title
	print "\n" + "-" * 35 + " " * 5 + usage_params["app_name"] + " - usage" + " " * 5 + "-" * 35
	print "\nUsage:"

	# mandatory params
	for param in usage_params["mandatory_params"]:
		print "\t%-35s - %s" % (str(param[KEY_IDX]), str(param[VALUE_IDX]))

	# optional params
	for param in usage_params["optional_params"]:
		print "\t%-35s - %s" % (str(param[KEY_IDX]), str(param[VALUE_IDX]))

	# example
	print "\n  Example:\n"

	# print example type
	example_type_keys = __example_col.keys()
	example_type_keys.sort()
	for example_type in example_type_keys:
		print "\t%s:" % str(example_type)
		# print all examples of example type 
		for example in __usage_params["example_cmd"][__example_col[example_type]]:
			print "\t\t%s.py %s\n" % (str(usage_params["app_name"]), str(example))

	# print bottom title
	print "-" * (80 + len(__usage_params["app_name"] + " - usage")) + "\n"


###################################################################################
############################## MAIN FUNCTIONS  ####################################
###################################################################################

##################################################################
# Function: convert_gid_to_guid
# expected gid_value = fe80:0000:0000:0000:0014:0500:0000:0017
# expected guid_value =  0x0014050000000017
# return value: guid_value - for success, "0x" - failure
##################################################################
def convert_gid_to_guid(gid_value):
    DEBUG_TRACE("Starting convert_gid_to_guid(gid_value = %s)" % str(gid_value))

    guid_value = "0x"
    gid_value_list = gid_value.split(":")[4:]
    DEBUG_TRACE("gid_value_list = %s" % str(gid_value_list))
    for gid_value in gid_value_list:
        guid_value = guid_value + gid_value

    DEBUG_TRACE("guid_value %s" % str(guid_value))
    return guid_value


##########################################################################
# Function :read_file
# Open file to read gets its output and close it
# Return value: (0, output) - success, (1, None) - failure
##########################################################################
def read_file(file_name):
#    (rc, output2) = run_command("cat " + str(file_name))
#    DEBUG_TRACE("rc %s, %s = %s" % (str(rc), str(file_name), str(output2)))

    try:
        file_name = file_name.replace("\\", "")
        fd = open(file_name, "r")
        output = fd.readline().strip('\n')
        rc = fd.close()
    except Exception, e:
        EXCEPTION("Failed to read file %s, (%s)" % (file_name, str(e)))
        output = None
        rc = 1

    #DATA_TRACE("%s = %s" % (str(file_name), str(output)))
    return (rc, output)


##########################################################################
# Function :get_value_from_virtual_lut
# Get the real value according to the virtual p-key by going to the real
# p-key table and fetch its value.
# Return value: (0, pkey value) - success, (1, None) - failure
##########################################################################
def get_value_from_real_lut(mlx_device, port, idx, real_table_path):
    DEVICE_PARAMS = {
                "<mlx_device>"  : mlx_device,
                "<port>"        : port,
    }

    if idx.find(INVALID_PKEY) != -1: # Invalid pkey index we will return 0x0000
        return (0, UNASSIGNED_PKEY)

    file_name = build_path(real_table_path, DEVICE_PARAMS) + idx
    (rc, output) = read_file(file_name)
    if rc:
         return (rc, None)
    output = output.replace("\n", "")
    if real_table_path.split("/")[-2] == "gids":
        output = convert_gid_to_guid(output)

    return (rc, output)


##########################################################################
# Function :get_value_from_virtual_lut
# Get the real value according to the virtual p-key by going to the real
# p-key table and fetch its value.
# Return value: (0, pkey value) - success, (1, None) - failure
##########################################################################
def get_value_from_virtual_lut(mlx_device, port, pci_device, idx, 
                                     real_table_path, virtual_table_path):
    DEBUG_TRACE("Starting get_value_from_virtual_lut")
    DEVICE_PARAMS = {
                "<mlx_device>"  : mlx_device,
                "<pci_device>"  : pci_device,
                "<port>"        : port,
    }


    file_name = build_path(virtual_table_path, DEVICE_PARAMS) + str(idx)
    (rc, output) = read_file(file_name)
    if rc:
        ERROR("Failed to get virtual table value")
        return (1, None)
    output = output.replace("\n", "")
    return get_value_from_real_lut(mlx_device, port, output, real_table_path)


##########################################################################
# Function : get_table_idx_list
# Description : 
#       return list of relevant elements for a specific table
# Return value : 
#       table_list
##########################################################################
def get_table_idx_list(pci_device, mlx_device, port, real_table_path, virtual_table_path):
    DEBUG_TRACE("Starting get_table_idx_list")
    DEBUG_TRACE("pci_device %s, mlx_device %s, port %s, real_table_path %s, virtual_table_path %s" % \
                (str(pci_device), mlx_device, port, real_table_path, str(virtual_table_path)))
    table_idx_list = []
    DEVICE_PARAMS = {
                "<mlx_device>"  : mlx_device,
                "<pci_device>"  : str(pci_device),
                "<port>"        : port,
    }

    if (pci_device != None) and (virtual_table_path != None):
        relevant_path = virtual_table_path
    else:
        relevant_path = real_table_path
    relevant_path = build_path(relevant_path, DEVICE_PARAMS)

    cmd = "ls " + relevant_path
    (rc, output) = run_command(cmd)
    if rc:
        ERROR("Failed to get table list")
        return (rc, table_idx_list)

    output = output.split("\n")
    for value in output:
        if value != "":
            try:
                value = int(value) # If possible, convert the string to int
            except Exception, e:
                pass
            table_idx_list.append(value)

    table_idx_list.sort()

    return (rc, table_idx_list)


##########################################################################
# Function : get_table
# Description : 
#       get pkey table per port
# Return value : 
#       (0, table_idx_list, mlx_table_list) - Success, (1, [], []) - Failure
##########################################################################
def get_table(pci_device, mlx_device, port, real_table_path, virtual_table_path):
    DEBUG_TRACE("Starting get_table")
    mlx_table = []

    table_name = get_table_name(pci_device, real_table_path)
    if pci_device != None:
        mlx_device = get_dom0_device_according_to_pci_device(pci_device)
        pci_device = "0000:" + pci_device
        pci_device = pci_device.replace(":", "\:")

        if mlx_device == None:
            ERROR("Failed to get mlx device")
            return (1, [])

    (rc, table_idx_list) = get_table_idx_list(pci_device, mlx_device, port, real_table_path, virtual_table_path)
    if rc:
        return (rc, table_idx_list, mlx_table)

    for idx in table_idx_list: # 0..126
        if (pci_device != None):
            (rc, pkey) = get_value_from_virtual_lut(mlx_device, port, pci_device, str(idx),
                                                          real_table_path, virtual_table_path)
        elif mlx_device != None:
            (rc, pkey) = get_value_from_real_lut(mlx_device, port, str(idx), real_table_path)
        if rc:
            ERROR("Failed to get %s %d" % (table_name, idx))
            return (rc, table_idx_list, mlx_table)
        mlx_table.append(pkey)

    DEBUG_TRACE("table_idx_list %s \n mlx_table %s" % (str(table_idx_list), str(mlx_table)))
    return (rc, table_idx_list, mlx_table)


##########################################################################
# Function : print_table_header
# Description : 
#       Print pkey table per port
# Return value : 
#       None
##########################################################################
def print_table_header(table_name, pci_device, mlx_device, port):

    if (TOOL_PARAMS["short-output"] == True):
        return

    header_str = "%s table for " % (table_name)
    if mlx_device != None:
        header_str += "device %s " % mlx_device
    if pci_device != None:
        header_str += "pci_device %s " % pci_device
    if port != None:
        header_str += "port %s" % port
    print header_str + ":"
    print "=" * (len(header_str) + 3)


##########################################################################
# Function : print_table
# Description : 
#       Print pkey table per port
# Return value : 
#       None
##########################################################################
def print_table(table_name, table_idx_list, mlx_table, pci_device, mlx_device, port):
    DEBUG_TRACE("Starting print_table")

    print_table_header(table_name, pci_device, mlx_device, port)
    if table_name.find("pkey") != -1:
        step = 8
    else:
        step = 4

    table_size = len(table_idx_list)
    for table_idx in range(0, table_size,step): # table_idx_list with interval of step
        for interval in range(step):
            idx = (int(table_idx_list[table_idx]) + interval)
            if idx >= table_size:
                break
            if (TOOL_PARAMS["short-output"] != True):
                print "[%d] = %s,	" % (idx, mlx_table[idx]),
            else:
                print "%s" % mlx_table[idx]
        if (TOOL_PARAMS["short-output"] != True):
            print ""
    if (TOOL_PARAMS["short-output"] != True):
        print ""

##########################################################################
# Function : get_device_params
# Description : 
#       return some devices params
# Return value : 
#       Tuple - (pci_device, mlx_device, port_list)
##########################################################################
def get_device_params(TOOL_PARAMS):
    DEBUG_TRACE("Starting get_device_params")
    rc = 1

    if TOOL_PARAMS.has_key("dev"):
        mlx_device      = TOOL_PARAMS["dev"]
    else:
        mlx_device      = None
    if TOOL_PARAMS.has_key("port"):
        port_list      = [TOOL_PARAMS["port"]]
    else:
        port_list      = [None]
    if TOOL_PARAMS.has_key("pci-dev"):
        pci_device      = TOOL_PARAMS["pci-dev"]
    else:
        pci_device      = None

    if ((None in port_list) or ("All" in port_list)) and ((pci_device != None) or (mlx_device != None)):
        port_list = get_port_list(mlx_device, pci_device)

    DEBUG_TRACE("pci_device %s, mlx_device %s, port_list %s" % (str(pci_device), str(mlx_device), str(port_list)))
    return (pci_device, mlx_device, port_list)


##########################################################################
# Function : get_table_name
# Description : 
#       Get table name and return it
# Return value : 
#       table_name
##########################################################################
def get_table_name(pci_device, real_table_path):
    if (pci_device == None) or (pci_device.find("00.0") != -1): # Is it virtual or physical table
        table_type = "physical "
    else:
        table_type = "virtual "
    table_name = real_table_path.split("/")[-2]
    table_name = table_type + table_name.replace("s", "")
    return table_name


##########################################################################
# Function : show_table
# Description : 
#       Dumps all table at specified port and pci device.
#       If no device is given, then the physical port is displayed
# Return value : 
#       0 - Success, 1 - Failure
##########################################################################
def show_table(TOOL_PARAMS, real_table_path, virtual_table_path = None):
    DEBUG_TRACE("Starting show_table(%s, %s)" % (real_table_path, str(virtual_table_path)))
    rc = 1

    (pci_device, mlx_device, port_list) = get_device_params(TOOL_PARAMS)
    table_name = get_table_name(pci_device, real_table_path)

    for port in port_list:
        (rc, table_idx_list, mlx_table) = get_table(pci_device, mlx_device, port, real_table_path, virtual_table_path)
        if rc:
            break
        print_table(table_name, table_idx_list, mlx_table, pci_device, mlx_device, port)

    return rc


##########################################################################
# Function : show_pkeys
# Description : 
#       Dumps all pkey table at specified port and pci device.
#       If no device is given, then the physical port is displayed
# Return value : 
#       0 - Success, 1 - Failure
##########################################################################
def show_pkeys(TOOL_PARAMS):
    return show_table(TOOL_PARAMS, REAL_PKEY_TABLE_PATH, VIRTUAL_P_KEY_LUT_PATH)


##########################################################################
# Function : show_guids
# Description : 
#       Dumps the gid table of the physical port, or a specific device
# Return value : 
#       0 - Success, 1 - Failure
##########################################################################
def show_guids(TOOL_PARAMS):
    return show_table(TOOL_PARAMS, REAL_GUID_TABLE_PATH, VIRTUAL_GUID_LUT_PATH)


##########################################################################
# Function : get_mcgs_dic
# Description : 
#       Return mgids dictionary for all existing mgids per port
#       For example:
#           mcgs_dic = { MGID : PARAM_LIST }
#                    = {ff12401bffff00000000000000000001 : 
#                       1, [00,00,03], 3, No, IDLE, OK, 0[1], 1[1], 2[1],
#                       ffff, b1b, 2, 4, 0, 2, 3, 0, 0, 0, 0 }
# Return value : 
#       (0, mcgs_dic) - Success, (1, {}) - Failure
##########################################################################
def get_mcgs_dic(mlx_device, port):
    mcgs_dic = {}
    DEVICE_PARAMS = {
                "<mlx_device>"  : mlx_device,
                "<port>"        : port,
    }

    (rc, mcgs_list) = get_table_idx_list(None, mlx_device, port, MGID_TABLE_PATH, None)
    if rc:
        return (rc, mcgs_dic)

    mgid_path = build_path(MGID_TABLE_PATH, DEVICE_PARAMS)
    DEBUG_TRACE("mcgs_list %s" % str(mcgs_list))
    for mgid in mcgs_list:
        (rc, output) = read_file(mgid_path + mgid)
        if rc:
            return (rc, {})

        mcgs_dic[mgid] = []
        output = output.replace("(", "")
        output = output.replace(")", "")
        output = output.replace("\t", "")
        mgid_param_list = output.split(" ")
        for mgid_param in mgid_param_list:
            if mgid_param != "":
                mcgs_dic[mgid].append(mgid_param)

    return (rc, mcgs_dic)


##########################################################################
# Function : print_mcgs_dic
# Description : 
#       Print multicast gids table
# Return value : 
#       None
##########################################################################
def print_mcgs_dic(mlx_device, port, mcgs_dic):
    param_name = ["JoinState", "join_state_ref", "Refs", "Pend", "State", "Consistency", "Func",
                  "P_Key", "Q_KEY", "MTUSelector", "MTU", "TClass", "RateSelector", "Rate",
                  "SL", "FlowLabel", "HopLimit", "ProxyJoin"]

    not_to_be_printed_param_list = ["JoinState", "Refs", "Pend", "State", "Consistency", "Func", 
                                    "MTUSelector", "RateSelector"]

    if (TOOL_PARAMS["short-output"] != True):
        print_table_header("mgid", None, mlx_device, port)
        header_str = "MGID                         	 Join State Ref	Pkey	Qkey	MTU	TClass	" \
                     "Rate	SL  FlowLabel HopLimit	ProxyJoin"
        print header_str
        print "=" * (len(header_str) + 20)

    for mgid in mcgs_dic.keys():
        mgid_params_str = ""

        param_idx = 0
        param_value_list = mcgs_dic[mgid]
        for param_idx_name in range(len(param_name)):
            # There are some parameters that we don't have to print - skip on them
            if param_name[param_idx_name] not in not_to_be_printed_param_list:
                if len(param_value_list[param_idx]) == 8:
                    mgid_params_str += param_value_list[param_idx] + " "
                else:
                    if param_name[param_idx_name] in ["Q_KEY"] :
                        mgid_params_str += param_value_list[param_idx] + "	 "
                    else:
                        mgid_params_str += param_value_list[param_idx] + "	"
            param_idx += 1

            # Special case can be more than one parameter
            if param_name[param_idx_name] == "Func":
                for idx in range(param_idx, len(param_value_list)):
                    if param_value_list[idx].find("[") == -1:
                        break
                param_idx = idx

        print "%s  %s" % (mgid, mgid_params_str)
    print ""


##########################################################################
# Function : show_mgids
# Description : 
#       Dumps para-virtual state of all mgids (for all virtual devices)
#       Cannot by specified in conjunction with pcidev
# Return value : 
#       0 - Success, 1 - Failure
##########################################################################
def show_mgids(TOOL_PARAMS):
    (pci_device, mlx_device, port_list) = get_device_params(TOOL_PARAMS)
    rc = 0

    if mlx_device == None:
        ERROR("Can't show mgid table without device parameter. Please provide one")
        return 1

    for port in port_list:
        (rc, mcgs_dic) = get_mcgs_dic(mlx_device, port)
        if rc:
            ERROR("Failed to get multicast gid table")
            break
        print_mcgs_dic(mlx_device, port, mcgs_dic)
    return rc


##########################################################################
# Function : get_ls_output_in_list
# Description : 
#       returns all ls output in list
# Return value : 
#       (rc, mlx_device_list) - Success, (1, []) - Failure
##########################################################################
def get_ls_output_in_list(path_to_ls):
    obj_list = []
    cmd = "ls " + path_to_ls
    (rc, output) = run_command(cmd)
    if rc:
        ERROR("Failed to get list")
        return (rc, [])

    output = output.split("\n")
    for obj in output:
        if obj != "":
            obj_list.append(obj)

    return (rc, obj_list)


##########################################################################
# Function : get_mlx_dev_pci_dev_dic
# Description : 
#       get all existing VFs that were created.
#       if a specific device is given only it's vfs will be shown
# Return value : 
#       (0, vfs_dic) - Success, (1, {}) - Failure
##########################################################################
def get_mlx_dev_pci_dev_dic(mlx_device = None):
    rc = 0
    mlx_dev_pci_dev_dic = {}

    if mlx_device == None:
        (rc, mlx_device_list) = get_ls_output_in_list(INFINIBAND_PATH)
        if rc:
            ERROR("Failed to get all Mellanox device list")
    else:
        mlx_device_list = [mlx_device]

    for mlx_device in mlx_device_list:
        mlx_dev_pci_dev_dic[mlx_device] = []

        pci_device_path = build_path(IOV_PATH, { "<mlx_device>"  : mlx_device })
        (rc, mlx_dev_pci_dev_dic[mlx_device]) = get_ls_output_in_list(pci_device_path)
        if rc:
            ERROR("Failed to get VFs for device %s" % mlx_device)
            return (rc, {})
        mlx_dev_pci_dev_dic[mlx_device].pop(len(mlx_dev_pci_dev_dic[mlx_device]) - 1)

    return (rc, mlx_dev_pci_dev_dic)


##########################################################################
# Function : print_vfs
# Description : 
#       Print all VF tables
# Return value : 
#       None
##########################################################################
def print_vfs(vfs_dic):
    for mlx_device in vfs_dic.keys():
        print_table("VFs", range(len(vfs_dic[mlx_device])), vfs_dic[mlx_device], None, mlx_device, None)
    return 0


##########################################################################
# Function : show_vfs
# Description : 
#       Dumps all existing VFs that were created.
#       if a specific device is given only it's vfs will be shown
# Return value : 
#       0 - Success, 1 - Failure
##########################################################################
def show_vfs(TOOL_PARAMS):
    (pci_device, mlx_device, port_list) = get_device_params(TOOL_PARAMS)

    (rc, vfs_dic) = get_mlx_dev_pci_dev_dic(mlx_device)
    if rc:
        ERROR("Failed to get VFs table")
        return rc
    print_vfs(vfs_dic)

    return rc


##########################################################################
# Function : find_pkey_idx
# Description : 
#       Return pkey index if the given pkey is found.
#       If the pkey is not found than -1 is return
# Return value : 
#       (0, pkey_idx) - Success, (1, -1) - Failure
##########################################################################
def find_pkey_idx(pkey_to_search, pci_device, mlx_device, port, real_table_path, virtual_table_path = None):
    global REAL_TABLE_VALUE_DIC
    global VIRTUAL_TABLE_VALUE_DIC
    global REAL_TABLE_INDEX_DIC
    global VIRTUAL_TABLE_INDEX_DIC
    pkey_idx = -1
    rc = 0

    if (virtual_table_path != None) and (VIRTUAL_TABLE_INDEX_DIC.has_key(port)):
        # Already got virtual table index don't have to re-read it
        table_idx_list = VIRTUAL_TABLE_INDEX_DIC[port]
    elif (virtual_table_path == None) and (REAL_TABLE_INDEX_DIC.has_key(port)):
        table_idx_list = REAL_TABLE_INDEX_DIC[port]
    else: # 1st time we call this function
        (rc, table_idx_list) = get_table_idx_list(pci_device, mlx_device, port, real_table_path, virtual_table_path)
        if rc:
            ERROR("Failed to get table list")
            return (rc, pkey_idx)
        if (virtual_table_path != None):
            VIRTUAL_TABLE_INDEX_DIC[port] = table_idx_list
        else:
            REAL_TABLE_INDEX_DIC[port] = table_idx_list

    for idx in table_idx_list:
        idx = int(idx)
        if virtual_table_path != None:
            if (VIRTUAL_TABLE_VALUE_DIC.has_key(port)) and (VIRTUAL_TABLE_VALUE_DIC[port].has_key(idx)):
                pkey = VIRTUAL_TABLE_VALUE_DIC[port][idx]
            else:
                (rc, pkey) = get_value_from_virtual_lut(mlx_device, port, pci_device, str(idx),
                                                              real_table_path, virtual_table_path)
                if not (VIRTUAL_TABLE_VALUE_DIC.has_key(port)):
                    VIRTUAL_TABLE_VALUE_DIC[port] = {}
                VIRTUAL_TABLE_VALUE_DIC[port][idx] = pkey
        else: # Real table
            if (REAL_TABLE_VALUE_DIC.has_key(port)) and (len(REAL_TABLE_VALUE_DIC[port]) > idx):
                pkey = REAL_TABLE_VALUE_DIC[port][idx]
            else:
                (rc, pkey) = get_value_from_real_lut(mlx_device, port, str(idx), real_table_path)
                if not (REAL_TABLE_VALUE_DIC.has_key(port)):
                    REAL_TABLE_VALUE_DIC[port] = {}
                REAL_TABLE_VALUE_DIC[port][idx] = pkey
        if rc:
            ERROR("Failed to get pkey at index %d" % idx)
            break
        if pkey.find(pkey_to_search) != -1:
            pkey_idx = idx
            break

    return (rc, pkey_idx)


##########################################################################
# Function : find_pkey_idx
# Description : 
#       Return pkey index if the given pkey is found.
#       If the pkey is not found than -1 is return
# Return value : 
#       (0, pkey_idx) - Success, (1, -1) - Failure
##########################################################################
def find_pkey_according_to_real_idx(real_pkey_idx, mlx_device, port, real_table_path):
    pkey_value = "-1"

    (rc, pkey_value) = get_value_from_real_lut(mlx_device, port, str(real_pkey_idx), real_table_path)
    if rc:
        ERROR("Failed to get pkey at index %s" % str(real_pkey_idx))
    DEBUG_TRACE("pkey_value %s" % pkey_value)
    return (rc, pkey_value)


##########################################################################
# Function : find_unused_pkey_idx
# Description : 
#       Return the 1st pkey index that found unused.
#       if all in use -1 will be returned
# Return value : 
#       (0, pkey_idx) - Success, (1, -1) - Failure
##########################################################################
def find_unused_pkey_idx(pci_device, mlx_device, port, real_table_path, virtual_table_path = None):
    return find_pkey_idx(UNASSIGNED_PKEY, pci_device, mlx_device, port, real_table_path, virtual_table_path)


##########################################################################
# Function : is_free_pkey_idx
# Description : 
#       Return true if the given pkey_idx is not in use
# Return value : 
#       (0, True) - Free index, (1, False) - index in use \ Failure
##########################################################################
def is_free_pkey_idx(pkey_idx, pci_device, mlx_device, port, real_table_path, virtual_table_path = None):
    is_free = False

    if virtual_table_path != None:
        (rc, pkey) = get_value_from_virtual_lut(mlx_device, port, pci_device, str(pkey_idx),
                                                      real_table_path, virtual_table_path)
    else: # Real table
        (rc, pkey) = get_value_from_real_lut(mlx_device, port, str(idx), real_table_path)
    if rc:
        ERROR("Failed to get pkey at index %s" % str(idx))
        return (rc, False)

    if (pkey.find(UNASSIGNED_PKEY) != -1) or (pkey.find(INVALID_PKEY) != -1):
        is_free = True

    return (rc, is_free)


##########################################################################
# Function : set_value
# Description : 
#       add new pkey from rael_pkey_idx to virtual_pkey_idx.
# Return value : 
#       0 - Success, 1 - Failure
##########################################################################
def set_value(value, idx, pci_device, mlx_device, port, table_path):
    pci_device = pci_device.replace(":", "\:")
    DEVICE_PARAMS = {
                "<mlx_device>"  : mlx_device,
                "<pci_device>"  : pci_device,
                "<port>"        : port,
    }

    cmd = "echo %s > %s" % (str(value), build_path(table_path, DEVICE_PARAMS) + str(idx))
    (rc, output) = run_command(cmd)
    if rc:
        ERROR("Failed to set value")
    return rc


##########################################################################
# Function : _add_del_pkey
# Description : 
#       according to action parameter we decide whether to add or delete.
#       Add new pkey to virtual pkey table.
#       valid only if pci-dev is given.
#       if pkey already exists, does nothing.
#       if virtual_pkey_idx is not given it will insert to the 
#       1st unused index.
#       if pkey is not given it will add the 
#       real_pkey_idx value.
# Return value : 
#       0 - Success, 1 - Failure
##########################################################################
def _add_del_pkey(action, pci_device, mlx_device, port_list,
                  pkey = None, real_pkey_idx = None, 
                  virtual_pkey_idx = None, only_validate_for_error = False,
                  dont_print_warning_msg = False):
    global VIRTUAL_TABLE_VALUE_DIC
    global VIRTUAL_TABLE_INDEX_DIC
    rc = 0

    if pci_device == None:
        ERROR("Can't %s pkey without pci-device" % action)
        return 1

    if (pkey == None) and (real_pkey_idx == None) and (virtual_pkey_idx == None):
        ERROR("Can't run this function without at least one pkey parameter")
        return 1

    if (pkey == None) and (action.find("delete") != -1) and (virtual_pkey_idx == None):
        ERROR("Can't delete virtual pkey without pkey or virtual_pkey_idx")
        return 1

    mlx_device = get_dom0_device_according_to_pci_device(pci_device)
    pci_device = "0000:" + pci_device
    if mlx_device == None:
        ERROR("Failed to get mlx device")
        return 1

    for port in port_list:
        # Delete operation
        if (action.find("delete") != -1):
            if virtual_pkey_idx == None: # find virtual_pkey_idx
                (rc, virtual_pkey_idx) = find_pkey_idx(pkey, pci_device, 
                                                       mlx_device, port, 
                                                       REAL_PKEY_TABLE_PATH, 
                                                       VIRTUAL_P_KEY_LUT_PATH)
                if rc:
                    ERROR("Failed to find pkey %s" % str(pkey))
                    return rc

                if virtual_pkey_idx == -1: # real pkey doesn't exist
                    if not only_validate_for_error:
                        WARNING("pkey %s doesn't exist in the real pkey-table" % pkey)
                    continue

            (rc, is_free_idx) = is_free_pkey_idx(virtual_pkey_idx,
                                                 pci_device, mlx_device,
                                                 port,
                                                 REAL_PKEY_TABLE_PATH,
                                                 VIRTUAL_P_KEY_LUT_PATH)
            if rc:
                ERROR("Failed to get pkey index")
                return rc
            if is_free_idx:
                if (not only_validate_for_error) and (not dont_print_warning_msg):
                    WARNING("pkey index %s is not in use, doing nothing" % virtual_pkey_idx)
                continue

            real_pkey_idx = INVALID_PKEY

        else: # Else..  Add operation
            # Check whether this pkey exist in the real pkey table
            add_err_msg = "please add it to real pkey-table before adding it to virtual."
            if pkey != None:
                (rc, real_pkey_idx) = find_pkey_idx(pkey, pci_device, 
                                                    mlx_device, port, 
                                                    REAL_PKEY_TABLE_PATH)
                if rc:
                    ERROR("Failed to find pkey index (in real pkey table)")
                    return rc
                if real_pkey_idx == -1: # real pkey doesn't exist
                    ERROR("pkey %s doesn't exist in the real pkey-table" % pkey)
                    ERROR(add_err_msg)
                    return 1

            elif real_pkey_idx != None: # pkey == None
                (rc, pkey) = find_pkey_according_to_real_idx(real_pkey_idx, mlx_device,
                                                             port, REAL_PKEY_TABLE_PATH)
                if rc:
                    ERROR("Failed to find pkey (in real pkey table)")
                    return rc
                if pkey.find("-1") != -1: # real pkey not exist
                    ERROR("pkey index %s is not exist in the real pkey-table" % 
                          real_pkey_idx)
                    ERROR(add_err_msg)
                    return 1

           # Check whether the virtual index already in use
            if virtual_pkey_idx != None:
                (rc, is_free_idx) = is_free_pkey_idx(virtual_pkey_idx,
                                                     pci_device, mlx_device,
                                                     port,
                                                     REAL_PKEY_TABLE_PATH,
                                                     VIRTUAL_P_KEY_LUT_PATH)
                if rc:
                    ERROR("Failed to get pkey index")
                    return rc
                if not is_free_idx:
                    if not only_validate_for_error:
                        WARNING("pkey index %s is in use, doing nothing" % 
                                virtual_pkey_idx)
                    continue

            # Check whether this pkey already exist in this virtual pkey-table
            (rc, pkey_idx) = find_pkey_idx(pkey, pci_device, 
                                           mlx_device, port,
                                           REAL_PKEY_TABLE_PATH, 
                                           VIRTUAL_P_KEY_LUT_PATH)
            if rc:
                ERROR("Failed to find pkey index")
                return rc
            if pkey_idx != -1: # pkey already exist
                if (not only_validate_for_error) and (not dont_print_warning_msg):
                    WARNING("pkey %s is already exist at %s, doing nothing with this pkey." % 
                                 (pkey, pkey_idx))
                continue

            if (virtual_pkey_idx == None):
                (rc, virtual_pkey_idx) = find_unused_pkey_idx(pci_device, mlx_device, port, 
                                                              REAL_PKEY_TABLE_PATH, VIRTUAL_P_KEY_LUT_PATH)
                if rc:
                    ERROR("Failed to find unused pkey index")
                    return rc
                if virtual_pkey_idx == -1:
                    ERROR("pkey table is full, please delete pkey to add new one")
                    return 1

            # Check whether pkey is valid and not pointing to unassigned pkey
            if (pkey.find(UNASSIGNED_PKEY) != -1):
                if not only_validate_for_error:
                    WARNING("pkey %s is unassigned, doing nothing" % pkey)
                continue

        DEBUG_TRACE("pkey %s, real_pkey_idx %s, virtual_pkey_idx %s"% (str(pkey), 
                                                                       str(real_pkey_idx), 
                                                                       str(virtual_pkey_idx)))
        if only_validate_for_error:
            DEBUG_TRACE("pkey %s at index %s was successfully checked" % (pkey, 
                                                                          str(virtual_pkey_idx)))
            continue

        # Update value
        rc = set_value(real_pkey_idx, virtual_pkey_idx, pci_device, mlx_device,
                            port, VIRTUAL_P_KEY_LUT_PATH)
        if rc:
            ERROR("Failed to %s pkey %s at index %s" % (action, str(pkey), 
                                                        str(virtual_pkey_idx)))
            return rc

        # Update virtual tables for next iteration
        if (VIRTUAL_TABLE_VALUE_DIC.has_key(port)) and (VIRTUAL_TABLE_VALUE_DIC[port].has_key(virtual_pkey_idx)):
            if action.find("add") != -1:
                VIRTUAL_TABLE_VALUE_DIC[port][virtual_pkey_idx] = pkey
            else:
                VIRTUAL_TABLE_VALUE_DIC[port][virtual_pkey_idx] = real_pkey_idx
            DEBUG_TRACE("VIRTUAL_TABLE_VALUE_DIC %s" % str(VIRTUAL_TABLE_VALUE_DIC))

        if action.find("add") != -1:
            action += "ed"
        else:
            action += "d"
            if pkey == None:
                pkey = ""
        MISC_TRACE("pkey %s was %s successfully at index %s" % (action, pkey, virtual_pkey_idx))

    return rc


##########################################################################
# Function : remove_duplicated_parameters
# Description : 
#       Check and fix whether there is a parameter that was 
#       given twice (mistakenly).
#       if a parameter was given more than one it will delete 
#       all duplications.
# Return value : 
#       new_param_list
##########################################################################
def remove_duplicated_parameters(param_list, step = 1, check_legal_idx = False):
    DEBUG_TRACE("remove_duplicated_parameters (%s, %s, %s)" % 
                (str(param_list), str(step) , str(check_legal_idx)))
    new_param_list = []

    max_warning_msg = "pkey index is more than the maximum (%d), skipping this pkey" % MAX_TABLE_SIZE
    for param_idx in range(0, len(param_list), step):
        param = param_list[param_idx]
        if (param not in new_param_list):
            if check_legal_idx: # Chcek for illegal index
                if int(param) > MAX_TABLE_SIZE:
                    WARNING("real %s %s" % (param, max_warning_msg))
                    continue
                if (step == 2) and (int(param_list[param_idx + 1]) > MAX_TABLE_SIZE):
                    WARNING("virtual %s %s" % (param_list[param_idx + 1], max_warning_msg))
                    continue

            new_param_list.append(param)
            if step == 2:
                new_param_list.append(param_list[param_idx + 1])
        else:
           WARNING("%s is duplicated, removing duplication" % str(param))
    DEBUG_TRACE("new_param_list %s" % str(new_param_list))
    return new_param_list


##########################################################################
# Function : add_pkey
# Description : 
#       valid only if pci-dev is given.
#       searches port pkey table and adds corresponding index to 
#       virtual pkey table at the first unused index.
#       if pkey already exists, does nothing.
#       if virtual_pkey_idx is not given it will insert to the 
#       1st unused index.
# Return value : 
#       0 - Success, 1 - Failure
##########################################################################
def add_pkey(TOOL_PARAMS, virtual_pkey_idx = None):
    rc = 0
    (pci_device, mlx_device, port_list) = get_device_params(TOOL_PARAMS)

    header_str = "Going to add pkeys:"
    print header_str
    print "=" * (len(header_str) + 3)

    pkey_table = remove_duplicated_parameters(TOOL_PARAMS["add-pkey"])
    # Before starting any changes with adding pkeys validate for errors
    for pkey in pkey_table:
        rc = _add_del_pkey("add", pci_device, mlx_device, port_list, 
                           pkey, only_validate_for_error = True) or rc
        DEBUG_TRACE("rc = %s" % str(rc))
    if rc:
        return 1

    for pkey in pkey_table:
        rc = _add_del_pkey("add", pci_device, mlx_device, port_list, pkey)
        if rc:
            break

    print ""
    return rc


##########################################################################
# Function : add_pkey_idx
# Description : 
#       Sets pkey at physical index <port phy index> in virtual index <virt idx>
#       if <virt index> exists, operation will fail.
# 
# Return value : 
#       0 - Success, 1 - Failure
##########################################################################
def add_pkey_idx(TOOL_PARAMS):
    rc = 0
    (pci_device, mlx_device, port_list) = get_device_params(TOOL_PARAMS)

    header_str = "Going to add pkeys:"
    print header_str
    print "=" * (len(header_str) + 3)

    # Before starting any changes with adding pkeys validate for errors
    step = 2
    pkey_table = TOOL_PARAMS["add-pkey-idx"]
    if (len(pkey_table) % 2):
        ERROR("The number of pkey indexes is odd, please fix it and rerun")
        return 1

    pkey_table = remove_duplicated_parameters(pkey_table, step, True)
    add_pkey_idx_list = range(0, len(pkey_table), step)

    for idx in add_pkey_idx_list: # Always takes tuple of (real_pkey_idx, virtual_pkey_idx)
        real_pkey_idx = pkey_table[idx]
        virtual_pkey_idx = pkey_table[idx + 1]
        rc = _add_del_pkey("add", pci_device, mlx_device, port_list,
                              None, real_pkey_idx, virtual_pkey_idx, True) or rc
    if rc:
        return 1

    for idx in add_pkey_idx_list: # Always takes tuple of (real_pkey_idx, virtual_pkey_idx)
        real_pkey_idx = pkey_table[idx]
        virtual_pkey_idx = pkey_table[idx + 1]
        rc = _add_del_pkey("add", pci_device, mlx_device, port_list, 
                           None, real_pkey_idx, virtual_pkey_idx)
        if rc:
            break

    print ""
    return rc


##########################################################################
# Function : del_pkey
# Description : 
#       Remove pkeys from virtual pkey table
# Return value : 
#       0 - Success, 1 - Failure
##########################################################################
def del_pkey(TOOL_PARAMS, virtual_pkey_idx = None):
    rc = 0
    (pci_device, mlx_device, port_list) = get_device_params(TOOL_PARAMS)

    header_str = "Going to delete pkeys:"
    print header_str
    print "=" * (len(header_str) + 3)

    pkey_table = remove_duplicated_parameters(TOOL_PARAMS["del-pkey"])
    for pkey in pkey_table:
        rc = _add_del_pkey("delete", pci_device, mlx_device, port_list, pkey)
        if rc:
            break

    print ""
    return rc


##########################################################################
# Function : del_pkey_idx
# Description : 
#       Remove pkey at specific virtual index
# Return value : 
#       0 - Success, 1 - Failure
##########################################################################
def del_pkey_idx(TOOL_PARAMS):
    rc = 0
    (pci_device, mlx_device, port_list) = get_device_params(TOOL_PARAMS)

    header_str = "Going to delete pkeys:"
    print header_str
    print "=" * (len(header_str) + 3)

    pkey_table = remove_duplicated_parameters(TOOL_PARAMS["del-pkey-idx"], 1, True)
    for pkey_idx in pkey_table:
        rc = _add_del_pkey("delete", pci_device, mlx_device, port_list, None, None, pkey_idx)
        if rc:
            break

    print ""
    return rc


##########################################################################
# Function : _set_guid
# Description : 
#       Set guid_value in guid index location in the real table.
#       If virtual_guid_table is given we'll find the real location 
#       and update in the real guid table.
# if guid_idx is given no need to supply virtual_guid_table
# Return value : 
#       0 - Success, 1 - Failure
##########################################################################
def _set_guid(pci_device, mlx_device, port,
             guid_value, guid_idx, real_guid_table, virtual_guid_table = None):
    rc = 0

    pci_device = "0000:" + str(pci_device)
    if virtual_guid_table != None: # Find the real guid index
        DEVICE_PARAMS = {
                    "<mlx_device>"  : mlx_device,
                    "<pci_device>"  : pci_device,
                    "<port>"        : port,
        }
    
        file_name = build_path(virtual_guid_table, DEVICE_PARAMS) + str(guid_idx)
        (rc, output) = read_file(file_name)
        if rc:
            ERROR("Failed to get virtual table value")
            return rc
        guid_idx = output.replace("\n", "") # replace virtual guid index with the real one

    rc = set_value(guid_value, guid_idx, pci_device, mlx_device, port, real_guid_table)
    return rc


##########################################################################
# Function : reset_guid
# Description : 
#       Operates on VFs only, 
#       Invalidates the default guid (index0) of the devices gid table
# Return value :
#       0 - Success, 1 - Failure
##########################################################################
def reset_guid(TOOL_PARAMS):
    rc = 0
    (pci_device, mlx_device, port_list) = get_device_params(TOOL_PARAMS)

    if pci_device == None:
        ERROR("Can't run without pci device parameter, please supply one")
        return 1

    mlx_device = get_dom0_device_according_to_pci_device(pci_device)
    if mlx_device == None:
        ERROR("Failed to get mlx device")
        return 1

    header_str = "Going to reset guid at pci-device %s" % pci_device
    print header_str
    print "=" * (len(header_str) + 3)
    for port in port_list:
        rc = _set_guid(pci_device, mlx_device, port,
                 DELETE_GUID_VALUE, DEFAULT_VIRT_GUID_IDX, ALIAS_GUID_PATH, VIRTUAL_GUID_LUT_PATH)
        if rc:
            break
        print "Successfully reset Guid at port %s\n" % port

    if rc:
        ERROR("Failed to reset guid at index %s" % DEFAULT_VIRT_GUID_IDX)
    return rc


##########################################################################
# Function : convert_guid
# Description : 
#       convert guid from any type of input to '0x12345678...'
# Return value :
#       0 - Success, 1 - Failure
##########################################################################
def convert_guid(guid_to_assign):
    guid_to_assign = guid_to_assign.replace(":", "")
    guid_to_assign = guid_to_assign.replace("0x", "")
    guid_to_assign = "0x" + guid_to_assign
    if int(guid_to_assign, 16) == 0: # Make sure we use 64-bits
        guid_to_assign = SM_ASSIGN_GUID_VALUE
    return guid_to_assign


##########################################################################
# Function : is_pci_has_assigned_guid
# Description : 
#       Check whether the specific pci-device has assigned guid
# Return value :
#       (0, True) - Success and has assigned guid, (1, ???) - Failure
##########################################################################
def is_pci_has_assigned_guid(pci_device, mlx_device, port):
    rc = 0
    is_pci_has_assigned_guid_flag = False

    (rc, table_idx_list, guid_table) = get_table(pci_device, mlx_device, port, REAL_GUID_TABLE_PATH, VIRTUAL_GUID_LUT_PATH)
    if rc:
        return (rc, is_pci_has_assigned_guid_flag)

    if EMPTY_GUID_VALUE not in guid_table:
        is_pci_has_assigned_guid_flag = True
    return (rc, is_pci_has_assigned_guid_flag)


##########################################################################
# Function : is_pci_has_assigned_guid
# Description : 
#       search within all mlx cards and pci-device whether the specific 
#       guid is in use any where.
#       if the 
# Return value :
#       (0, True) - Success and has assigned guid, (1, ???) - Failure
##########################################################################
def is_guid_in_use(pci_device, mlx_device, port, guid_to_assign):
    rc = 0
    is_guid_in_use_flag = False

    (rc, mlx_dev_pci_dev_dic) = get_mlx_dev_pci_dev_dic() # All mlx-device and pci-device
    if rc:
        return (rc, is_guid_in_use_flag)

    for curr_mlx_device in mlx_dev_pci_dev_dic.keys():
        for curr_pci_device in mlx_dev_pci_dev_dic[curr_mlx_device]:
            curr_pci_device = curr_pci_device.replace("0000:", "")
            if (curr_mlx_device == mlx_device) and (curr_pci_device == pci_device):
                continue # Don't check for my device

            (rc, table_idx_list, guid_table) = get_table(curr_pci_device, curr_mlx_device, port, REAL_GUID_TABLE_PATH, VIRTUAL_GUID_LUT_PATH)
            if rc:
                return (rc, is_guid_in_use_flag)
        
            if guid_to_assign in guid_table:
                is_guid_in_use_flag = True
                break

    return (rc, is_guid_in_use_flag)


##########################################################################
# Function : set_guid
# Description : 
#       Operates on VFs only.
#       Sets the default guid, which corresponds to the gid at index 0
#       in the devices gid table.
#       Fails if device already has an assigned guid or the guid is 
#       already in use by another device.
#       <guid>=0 means SM assigned gid.
#       Note: call returns when the administrative state of the gid 
#       has been set operation state change may occur at a later time.
# Return value :
#       0 - Success, 1 - Failure
##########################################################################
def set_guid(TOOL_PARAMS):
    rc = 0
    (pci_device, mlx_device, port_list) = get_device_params(TOOL_PARAMS)

    if (pci_device == None):
        ERROR("Can't run without pci device parameter, please supply one")
        return 1
    if len(port_list) != 1:
        ERROR("Only one port can be given when setting guid, please supply one")
        return 1

    port = port_list[0] # Only one port is allow
    guid_to_assign = convert_guid(TOOL_PARAMS["set-guid"])
    mlx_device = get_dom0_device_according_to_pci_device(pci_device)
    if mlx_device == None:
        ERROR("Failed to get mlx device")
        return 1

    header_str = "Going to set guid %s at pci-device %s at port %s" % \
                 (guid_to_assign, pci_device, port)
    print header_str
    print "=" * (len(header_str) + 3)

    # Check whether the device has an assigned guid
    (rc, is_invalid_action) = is_pci_has_assigned_guid(pci_device, mlx_device, port)
    if rc:
        ERROR("Failed to query is_pci_has_assigned_guid")
        return rc
    if is_invalid_action:
        ERROR("pci %s has an assigned guid, doing nothing" % pci_device)
        return 1

    # Check whether the guid is already in use
    (rc, is_invalid_action) = is_guid_in_use(pci_device, mlx_device, port, guid_to_assign)
    if rc:
        ERROR("Failed to query is_guid_in_use")
        return rc
    if is_invalid_action:
        ERROR("guid %s is in use. doing nothing" % guid_to_assign)
        return 1

    rc = _set_guid(pci_device, mlx_device, port,
                   guid_to_assign, DEFAULT_VIRT_GUID_IDX, ALIAS_GUID_PATH, VIRTUAL_GUID_LUT_PATH)

    if rc:
        ERROR("Failed to set guid %s at index %s" % (guid_to_assign, DEFAULT_VIRT_GUID_IDX))
    else:
        print "Successfully set Guid %s" % guid_to_assign

    return rc


##########################################################################
# Function : get_table_as_string
# Description : 
#       Get table configurations of specific device or pci device
# Return value :
#       0 - Success, 1 - Failure
##########################################################################
def get_table_as_string(pci_device, mlx_device, port, real_table_path, virtual_table_path):
    (rc, table_idx_list, mlx_table) = get_table(pci_device, mlx_device, port,
                                                real_table_path, 
                                                virtual_table_path)
    if rc:
        ERROR("Failed to get table")
    return (rc, mlx_table)


##########################################################################
# Function : get_guid_as_string
# Description : 
#       Get guid configurations of specific device or pci device
# Return value :
#       0 - Success, 1 - Failure
##########################################################################
def get_guid_as_string(pci_device, mlx_device, port): 
    return get_table_as_string(pci_device, mlx_device, port,
                               REAL_GUID_TABLE_PATH, VIRTUAL_GUID_LUT_PATH)


##########################################################################
# Function : get_guid_as_string
# Description : 
#       Get pkey configurations of specific device or pci device
# Return value :
#       0 - Success, 1 - Failure
##########################################################################
def get_pkey_as_string(pci_device, mlx_device, port):
    return get_table_as_string(pci_device, mlx_device, port,
                               REAL_PKEY_TABLE_PATH, VIRTUAL_P_KEY_LUT_PATH)


##########################################################################
# Function : save_data_file
# Description : 
#       Save 'data_to_be_written' string at file_name
# Return value :
#       0 - Success, 1 - Failure
##########################################################################
def save_data_file(file_name, data_to_be_written):
    try:
        fd = open(file_name, "w")
        fd.writelines(data_to_be_written)
        rc = fd.close()
    except Exception, e:
        EXCEPTION("Failed to read file %s, (%s)" % (file_name, str(e)))
        output = None
        rc = 1

    return rc


##########################################################################
# Function : get_all_pci_device
# Description : 
#       Return all pci_device_list for specific mlx_device
# Return value :
#       (0, pci_deivce_list) - Success, (1, []) - Failure
##########################################################################
def get_all_pci_device(mlx_device):
    pci_deivce_list = []
    pci_deivce_path = build_path(IOV_PATH, { "<mlx_device>"  : mlx_device })
    (rc, tmp_pci_deivce_list) = get_ls_output_in_list(pci_deivce_path)
    if rc:
        ERROR("Failed to get guid table")
        return (1, pci_deivce_list)
    tmp_pci_deivce_list.remove("ports")

    for pci_device in tmp_pci_deivce_list:
        pci_device = pci_device.replace("0000:", "")
        pci_deivce_list.append(pci_device)

    return (0, pci_deivce_list)


##########################################################################
# Function : save
# Description : 
#       Save guid and pkey configurations of
#       specific device or pci device
# Return value :
#       0 - Success, 1 - Failure
##########################################################################
def save(TOOL_PARAMS):
    (pci_device, mlx_device, port_list) = get_device_params(TOOL_PARAMS)
    file_name = TOOL_PARAMS["save"]

    if len(port_list) > 1:
        ERROR("Can't save guid and pkey on more than one port")
        return 1

    for port in port_list:
        if pci_device != None: # Save specific pci-device
            (rc, guid_str) = get_guid_as_string(pci_device, mlx_device, port)
            if rc:
                ERROR("Failed to get guid")
                break
            (rc, pkey_str) = get_pkey_as_string(pci_device, mlx_device, port)
            if rc:
                ERROR("Failed to get pkey table")
                break

            # Save data as dictionary
            data_to_be_written = "# This is a specific pci-device (%s) configurations\n" % pci_device

        else: # Save the whole card configurations
            (rc, guid_str) = get_guid_as_string(None, mlx_device, port) # Save the whole guid table
            if rc:
                ERROR("Failed to get guid")
                break

            (rc, pci_deivce_list) = get_all_pci_device(mlx_device)
            if rc:
                ERROR("Failed to get pci-device list")
                break

            pkey_str = ""
            for pci_device in pci_deivce_list:
                (rc, tmp_pkey_str) = get_pkey_as_string(pci_device, mlx_device, port) # Save pkey for each VF
                if rc:
                    ERROR("Failed to get pkey table")
                    break
                pkey_str += str(tmp_pkey_str) + ",\n"
            if rc:
                break

            # Save data as dictionary
            data_to_be_written = "# This is a mlx-device configurations\n"

        data_to_be_written += "{'dev_conf' : \n"
        data_to_be_written += "[\n"
        data_to_be_written += str(guid_str)
        data_to_be_written += ",\n"
        data_to_be_written += str(pkey_str)
        data_to_be_written += "]\n"
        data_to_be_written += "}\n"

        rc = save_data_file(file_name, data_to_be_written)
        if rc:
            ERROR("Failed to save_data_file")
            break

    return rc


##########################################################################
# Function : eval_file
# Description : 
#       Read test file and covert it to dictionary
# Return value :
#       0 - Success, 1 - Failure
##########################################################################
def eval_file(fn):
    ret = None

    f = open(fn, "r")
    if f != None:
       try:
           lines = f.readlines()
           f.close()
           s = "";
       except Exception, e:
           ERROR("Failed evaluating \"%s\".\n%s\n" % (fn, str(e)))
           ret = None
           return ret

       for l in lines:
           l = l.replace('\r', ''); # Accept DOS text files
           s += l

       try:
           ret = eval(s)
           if ret == None:
               ERROR("%s evaluated to None" % fn)
       except Exception, e:
           ERROR("Failed evaluating \"%s\".\n%s\n" % (fn, str(e)))
           ret = None
    else:
        ERROR("Failed opening \"%s\" for eval\n" % fn)
    return ret


##########################################################################
# Function : _get_file_type
# Description : 
#       Return whether this file is a pci type of mlx file type
# Return value :
#       (0, "pci"/"mlx") - Success, (1, "") - Failure
##########################################################################
def _get_file_type(fn):
    file_type = ""

    try:
        f = open(fn, "r")
        lines = f.read()
        f.close()
    except Exception, e:
        ERROR("Failed reading file \"%s\".\n%s\n" % (fn, str(e)))
        return (1, file_type)

    if lines.find("pci") != -1:
        file_type = "pci"
    else:
        file_type = "mlx"

    return (0, file_type)


##########################################################################
# Function : set_guid_table
# Description : 
#       Set the whole guid table
# Return value :
#       0 - Success, 1 - Failure
##########################################################################
def set_guid_table(mlx_device, port, guid_table):
    rc = 0

    header_str = "Going to set guid table at device %s, port %s" % (mlx_device, port)
    print header_str
    print "=" * (len(header_str) + 3)

    for guid_idx in range(len(guid_table)):
        if guid_idx == 0: # Skip idx #0 - Can't be written thru sysfs
            continue

        guid_value = guid_table[guid_idx]
        rc = _set_guid(None, mlx_device, port, guid_value, guid_idx, ALIAS_GUID_PATH, None)
        if rc:
            ERROR("Failed to write guid %s at idx %s" % (guid_value, guid_idx))
            break

    if not rc:
        print "Successfully set guid table\n"
    return rc


##########################################################################
# Function : restore
# Description : 
#       Restore guid and pkey configurations of
#       specific device or pci device
# Return value :
#       0 - Success, 1 - Failure
##########################################################################
def restore(TOOL_PARAMS):
    (pci_device, mlx_device, port_list) = get_device_params(TOOL_PARAMS)
    file_to_restore = TOOL_PARAMS["restore"]

    if len(port_list) > 1:
        ERROR("Can't restore guid and pkey on more than one port")
        return 1

    guid_and_pkey_dic = eval_file(file_to_restore)
    if guid_and_pkey_dic == None:
        return 1

    (rc, file_type) = _get_file_type(file_to_restore)
    if rc:
        ERROR("Failed to read file %s" % file_to_restore)
        return 1

    port = port_list[0]

    if (pci_device != None) and (file_type.find("pci") != -1): # Specific pci device
        # Restore specific pci-device
        guid_table = guid_and_pkey_dic["dev_conf"][0]
        pkey_table = guid_and_pkey_dic["dev_conf"][1]

        # Write guid table
        TOOL_PARAMS["set-guid"] = guid_table[0]
        rc = set_guid(TOOL_PARAMS)
        if rc:
            return rc

        # Verify that there's no error in the file
        for pkey_idx in range(len(pkey_table)):
            if pkey_idx == 0: # won't change
                continue 
            rc = _add_del_pkey("add", pci_device, mlx_device, port_list,
                               pkey_table[pkey_idx], None, pkey_idx,
                               only_validate_for_error = True)
            if rc:
                ERROR("Failed to add pkey")
                break

        # Write pkey table
        if not rc:
            for pkey_idx in range(len(pkey_table)):
                #if pkey_idx == 0: # won't change
                #    continue 
                rc = _add_del_pkey("add", pci_device, mlx_device, port_list,
                                   pkey_table[pkey_idx], None, pkey_idx,
                                   dont_print_warning_msg = True)
                if rc:
                    ERROR("Failed to add pkey")
                    break

    elif (pci_device == None) and (file_type.find("pci") == -1): 
        # Restore the whole card configurations
        guid_table = guid_and_pkey_dic["dev_conf"][0]
        pkey_table_list = guid_and_pkey_dic["dev_conf"][1:]

        (rc, pci_device_list) = get_all_pci_device(mlx_device)
        if rc:
            ERROR("Failed to get pci-device list")
            return rc

        # Write guid table
        rc = set_guid_table(mlx_device, port, guid_table)
        if rc:
            return rc

        # Write pkey table
        for (pci_device, pkey_table) in map(None, pci_device_list, pkey_table_list):
            header_str = "Going to set pkey table at pci device %s" % pci_device
            print header_str
            print "=" * (len(header_str) + 3)

            for pkey_idx in range(len(pkey_table)):
                if pkey_idx == 0: # won't change
                    continue 
                rc = _add_del_pkey("add", pci_device, mlx_device, port_list,
                                   pkey_table[pkey_idx], None, pkey_idx,
                                   only_validate_for_error = True)
                if rc:
                    ERROR("Failed to add pkey")
                    return 1

            # Write pkey table
            if not rc:
                for pkey_idx in range(len(pkey_table)):
                    #if pkey_idx == 0: # won't change
                    #    continue 
                    rc = _add_del_pkey("add", pci_device, mlx_device, port_list,
                                       pkey_table[pkey_idx], None, pkey_idx,
                                       dont_print_warning_msg = True)
                    if rc:
                        ERROR("Failed to add pkey")
                        break

            if not rc:
                print "Successfully set pkey table\n"
    else:
        ERROR("The file %s that was given is %s type, but the relevant parametes weren't given" % (file_to_restore, file_type)) 
        rc = 1

    return rc


##########################################################################
# Function : reset_pkey_table
# Description : 
#       Operates on VFs only, 
#       Invalidates pkey table of specific VF
# Return value :
#       0 - Success, 1 - Failure
##########################################################################
def reset_pkey_table(pci_device, mlx_device, port):
    rc = 0
    if pci_device == None:
        ERROR("Can't run without pci device parameter, please supply one")
        return 1

    mlx_device = get_dom0_device_according_to_pci_device(pci_device)
    if mlx_device == None:
        ERROR("Failed to get mlx device")
        return 1

    header_str = "Going to reset pkey table at pci-device %s" % pci_device
    print header_str
    print "=" * (len(header_str) + 3)

    DEVICE_PARAMS = {
                "<mlx_device>"  : mlx_device,
                "<pci_device>"  : "0000:" + pci_device,
                "<port>"        : port,
    }
    pkey_table_path = build_path(VIRTUAL_P_KEY_LUT_PATH, DEVICE_PARAMS)
    (rc, pkey_table) = get_ls_output_in_list(pkey_table_path)
    if rc:
        ERROR("Failed to get pkey table for pci device %s" % pkey_table_path)
        return rc

    for pkey_idx in pkey_table:
        rc = _add_del_pkey("delete", pci_device, mlx_device, [port], None, None, 
                           pkey_idx, only_validate_for_error = True)
        if rc:
            break

    if not rc:
        for pkey_idx in pkey_table:
            rc = _add_del_pkey("delete", pci_device, mlx_device, [port], None, None, 
                               pkey_idx, dont_print_warning_msg = True)
            if rc:
                break

    if not rc:
        print "Successfully reset pkey table at port %s\n" % port
    if rc:
        ERROR("Failed to reset pkey table for pci device %s" % pci_device)
    return rc


##########################################################################
# Function : _reset_physical_guid_table
# Description : 
#       Reset the whole physical guid table.
# Return value :
#       0 - Success, 1 - Failure
##########################################################################
def _reset_physical_guid_table(mlx_device, port):
    header_str = "Going to reset physical guid table for device " + mlx_device
    print header_str
    print "=" * (len(header_str) + 3)

    DEVICE_PARAMS = {
                "<mlx_device>"  : mlx_device,
                "<port>"        : port,
    }

    guid_table_path = build_path(ALIAS_GUID_PATH, DEVICE_PARAMS)
    (rc, guid_list) = get_ls_output_in_list(guid_table_path)
    if rc:
        ERROR("Failed to get guid table (%s)" % guid_table_path)
        return rc
    guid_idx_list = range(1, len(guid_list)) # We mustn't change guid #0

    for guid_idx in guid_idx_list:
        rc = _set_guid(None, mlx_device, port,
                 DELETE_GUID_VALUE, guid_idx, ALIAS_GUID_PATH)
        if rc:
            break

    if rc:
        ERROR("Failed to reset guid at port %s" % port)
    else:
        print "Successfully reset physical Guid table at port %s\n" % port

    return rc


##########################################################################
# Function : reset
# Description :
#       Operates on VFs only,
#       Invalidates gid and pkeys table of the
#       devices gid table
# Return value :
#       0 - Success, 1 - Failure
##########################################################################
def reset(TOOL_PARAMS):
    run_reset_guid_for_the_1st_time = True

    (pci_device, mlx_device, port_list) = get_device_params(TOOL_PARAMS)
    for port in port_list:
        if pci_device == None: # We will run on all pci_deivce and reset
            rc = _reset_physical_guid_table(mlx_device, port)
            if rc:
                break

            (rc, pci_deivce_list) = get_all_pci_device(mlx_device)
            if rc:
                ERROR("Failed to get pci-device list")
                break

            for pci_device in pci_deivce_list:
                rc = reset_pkey_table(pci_device, mlx_device, port)
                if rc:
                    break
        else: # Reset specific pci-device
            if run_reset_guid_for_the_1st_time: # run it only for the 1st time
                rc = reset_guid(TOOL_PARAMS)
                if rc:
                    break
            run_reset_guid_for_the_1st_time = False
            rc = reset_pkey_table(pci_device, mlx_device, port)
            if rc:
                break

    return rc


##########################################################################
# Function : verify_guids
# Description :
#       Verify that Guid table for VF 2 was updated.
#       Read from alias_guid and compare it to gids.
# Return value :
#       0 - Success, 1 - Failure
##########################################################################
def verify_guids(TOOL_PARAMS):
    (pci_device, mlx_device, port_list) = get_device_params(TOOL_PARAMS)

    for port in port_list:
        if pci_device == None: # We will run on all guid table
            virtual_guid_table_path = None
        else: # Specific pci-device
            virtual_guid_table_path = VIRTUAL_GUID_LUT_PATH

        (rc, table_idx_list, alias_guid_table) = get_table(pci_device, mlx_device, 
                                                           port, ALIAS_GUID_PATH, 
                                                           virtual_guid_table_path) # Should be None ????
        if rc:
            ERROR("Failed to get alias guid table")
            return rc

        (rc, table_idx_list, acual_guid_table) = get_table(pci_device, mlx_device, 
                                                           port, REAL_GUID_TABLE_PATH, 
                                                           virtual_guid_table_path)
        if rc:
            ERROR("Failed to get actual guid table")
            return rc

        guid_idx = 0
        for (alias_guid, actual_guid) in map(None, alias_guid_table, acual_guid_table):
            if guid_idx == 0:
                guid_idx += 1
                continue 

            try:
                if int(alias_guid, 16) != int(actual_guid, 16):
                    ERROR("Actual guid %s is diffent than requested %s at idx %d" % (alias_guid, actual_guid, guid_idx))
                    rc = 1
                guid_idx += 1
            except Exception, e:
                ERROR("illegal guid value at idx %d, actual guid %s, requested guid %s" % (guid_idx, actual_guid, alias_guid))
                return rc

    return rc

##########################################################################
# Function : start_tool
# Description :
#       The main function that dispatch the queries to small actions
# Return value :
#       0 - Success, 1 - Failure
##########################################################################
def start_tool(TOOL_PARAMS):
    DEBUG_TRACE("Starting start_tool")
    rc = 0

    MAIN_FUNCTION_DIC = {
        # Show function will always be ran after add\delete function
        "show_pkeys"                   : show_pkeys,
        "show_guids"                   : show_guids,
        "show_mgids"                   : show_mgids,
        "show_vfs"                     : show_vfs,
        "verify_guids"                 : verify_guids,
        # Migration actions
        "save"                         : save,
        "reset"                        : reset,
        "restore"                      : restore,
        # Action operation will run first
        "add_pkey"                     : add_pkey,
        "add_pkey_idx"                 : add_pkey_idx,
        "del_pkey"                     : del_pkey,
        "del_pkey_idx"                 : del_pkey_idx,
        "reset_guid"                   : reset_guid,
        "set_guid"                     : set_guid,
        }

    # Start running all actions one by one
    action_list = TOOL_PARAMS.keys()
    action_list.sort() # First do all action then show tables
    for action in action_list:
        if (TOOL_PARAMS[action] != False):
            action = action.replace("-", "_")
            if action in MAIN_FUNCTION_DIC.keys():
                rc = MAIN_FUNCTION_DIC[action](TOOL_PARAMS)
                if rc:
                    ERROR("failed running %s" % action)
                    break
    return rc


##########################################################################
# Function : is_pkey_operation_invalid
# Description : 
#       Verify whether there are pkey operation.
#       If there are it check whether the current pci is in use.
#       If yes return 1 (invalid)
# Return value : 
#       0 - pkey operation is valid, 1 - else.
##########################################################################
def is_pkey_operation_invalid(TOOL_PARAMS):
    # Verify whether there are pkey operation.
    found_pkey_operation = False
    for pkey_operation in PKEY_OPERATION_LIST:
        if TOOL_PARAMS.has_key(pkey_operation):
            found_pkey_operation = True
            break
    if found_pkey_operation == False:
        return 0

    if not TOOL_PARAMS.has_key("pci-dev"):
        ERROR("Can't run pkey operation without pci-device")
        return 1

    (rc, output) = run_command(XEN_IF_COMMAND + ASSIGNABLE_PCI_LIST)
    if rc:
        ERROR("Failed to run xm command, is xen running ?")
        return 1

    output = output.split("\n")
    if ("0000:" + TOOL_PARAMS["pci-dev"]) not in output:
        ERROR("pci device is in use by Dom-U")
        ERROR("Can't change pkey while in use by VM, please destroy VM")
        return 1

    return 0


##########################################################################
# Function : verify_dev_parameter
# Description : 
#       Verify whether the given parameters are a valid parameter.
# Return value : 
#       0 - dev param is valid, 1 - else.
##########################################################################
def verify_parameter(TOOL_PARAMS):
    (pci_device, mlx_device, port_list) = get_device_params(TOOL_PARAMS)

    if (mlx_device == None) and (pci_device == None):
        ERROR("Both mlx-device and pci-device are not defined")
        ERROR("Please supply at least one of these params to run this function")
        return 1

    if mlx_device != None:
        # get all existing Mellanox devices and check whether 
        # the given one is valid
        (rc, mlx_device_list) = get_device_list()
        if rc:
            return rc
        if mlx_device not in mlx_device_list:
            ERROR("dev parameter %s is invalid, please use one of the following %s" % (mlx_device, str(mlx_device_list)))
            return 1

    if pci_device != None:
        found_pci_device = False
        # Check whether this pci-device is exist in this machines and valid
        (rc, mlx_dev_pci_dev_dic) = get_mlx_dev_pci_dev_dic()
        if rc:
            ERROR("Failed to get pci-devices")
            return 1

        for curr_mlx_device in mlx_dev_pci_dev_dic.keys():
            if ("0000:" + pci_device) in mlx_dev_pci_dev_dic[curr_mlx_device]:
                found_pci_device = True
                break
        if not found_pci_device:
            pci_device = str(pci_device)
            pci_device = pci_device.replace("0000:", "")
            ERROR("pci device %s is illegal, try using one of the following:" % pci_device)
            for curr_mlx_device in mlx_dev_pci_dev_dic.keys():
                ERROR("%s" % str(mlx_dev_pci_dev_dic[curr_mlx_device]))
            return 1

    if len(port_list) > 1 :
        only_one_port_action_list = ["add-pkey" "add-pkey-idx", "del-pkey",
                                     "del-pkey-idx", "set-guid", "reset-guid"]
        for action in only_one_port_action_list:
            if TOOL_PARAMS.has_key(action) and (TOOL_PARAMS[action] != False):
#                        if  and (TOOL_PARAMS[action] in only_one_port_action_list):
                ERROR("%s can run only on one port, please set a port to use" % action)
                return 1

    for port in port_list:
        # Check whether this port is valid
        curr_port_list = get_port_list(mlx_device, pci_device)
        if port not in curr_port_list:
            ERROR("Port %s is not valid, please use one of the following %s" % (str(port), str(curr_port_list)))
            return 1

    if is_pkey_operation_invalid(TOOL_PARAMS):
        return 1

    return 0


##########################################################################
# Function : define_params
# Description : define params
# Return value : None
##########################################################################
def define_params():
    DEBUG_TRACE("Starting define_params")

    add_name(APP_NAME)
    add_example_command("--dev=mlx4_0 --port=1 --show-pkeys --show-guids --show-mgids --show-vfs", "1. Show current state of physical port")
    add_example_command("--pci-dev=09:00.0 --dev=mlx4_0 --port=1 --show-pkeys --show-guids", "2. Show current state of the PF (e.g., to validate that it is already a full member of the default partition)")

    add_example_command("--pci-dev=09:00.1 --port=1 --set-guid=0002:c903:00d4:1111", "3. Configure guids of the first port for VF 1 - 09:00.1")
    add_example_command("--pci-dev=09:00.2 --port=1 --set-guid=0x0002c90300d42222", "4. Configure guids of the first port for VF 2 - 09:00.2")

    add_example_command("--pci-dev=09:00.1 --port=1 --add-pkey=0x8001,0x8f01,0x7fff", "5. Assign pkeys (that are were assigned to the physical port) to VF 1")
    add_example_command("--pci-dev=09:00.2 --port=1 --add-pkey=0x8001,0x8f01,0x7fff", "6. Assign pkeys (that are were assigned to the physical port) to VF 2")

    add_example_command("--pci-dev=09:00.1 --port=1 --add-pkey-idx=10,12", "7. Assign pkey that located in 10th place in the real pkey-table to the virtual at 12th place")
    add_example_command("--pci-dev=09:00.2 --port=1 --add-pkey-idx=10,12", "8. Assign pkey that located in 10th place in the real pkey-table to the virtual at 12th place")

    add_example_command("--pci-dev=09:00.1 --port=1 --show-pkeys --show-guids", "9. Validate that the VF 1 configurations were applied correctly")
    add_example_command("--pci-dev=09:00.2 --port=1 --show-pkeys --show-guids", "A. Validate that the VF 2 configurations were applied correctly")

    add_example_command("--pci-dev=09:00.1 --port=1 --save=guid_n_pkey_vf1.conf", "B. Save Guid and pkeys table for VF 1")
    add_example_command("--pci-dev=09:00.1 --port=1 --reset", "C. Reset Guid and pkeys table for VF 1")
    add_example_command("--pci-dev=09:00.2 --port=1 --restore=guid_n_pkey_vf1.conf", "D. Restore Guid and pkeys table for VF 2 (Migrate VF 1 to 2)")
    add_example_command("--pci-dev=09:00.2 --port=1 --verify_guids", "E. Verify that Guid table for VF 2 was updated")

    add_parameter("dev", "Mellanox device name (e.g., mlx4_0, mlx4_1).", 
                          is_mandatory = False, is_numeric = False, default_value = None, print_param = True)

    add_parameter("pci-dev", "Pci device ID (e.g., 09:00:0, 13.00.1).", 
                          is_mandatory = False, is_numeric = False, default_value = None, print_param = True)

    add_parameter("port", "Port number(e.g., 1,2, All). If a port is not " \
      "                                              specified, the default value (All) is used,", 
                          is_mandatory = False, is_numeric = False, default_value = None, print_param = True)


    add_parameter("add-pkey", "valid only if pci-dev is given \n" \
     "                                              searches port pkey table and adds corresponding index to virtual pkey table at the first unused index\n" \
     "                                              if pkey is not exists in the real pkey table, does nothing"
     "                                              if pkey already exists in the virtual pkey table, does nothing", 
                          is_mandatory = False, is_numeric = False, default_value = None, print_param = True)

    add_parameter("add-pkey-idx", "Sets pkey at physical index <port phy index> in virtual index <virt idx> \n" \
     "                                              if <virt index> exists, operation will fail", 
                          is_mandatory = False, is_numeric = False, default_value = None, print_param = True)

    add_parameter("del-pkey", "Remove pkeys from virtual pkey table", 
                          is_mandatory = False, is_numeric = False, default_value = None, print_param = True)

    add_parameter("del-pkey-idx", "Remove pkey at specific virtual index", 
                          is_mandatory = False, is_numeric = False, default_value = None, print_param = True)

    add_parameter("set-guid", "Operates on VFs only.\n" \
     "                                              Sets the default guid, which corresponds to the gid at index 0 in the devices gid table\n" \
     "                                              Fails if device already has an assigned guid or the guid is already in use by another device\n" \
     "                                              <guid>=0 means SM assigned gid\n" \
     "                                              guid parameter can be given w/o ':' and '0x'\n" \
     "                                              Note: call returns when the administrative state of the gid has been set; \n" \
     "                                              operation state change may occur at a later time\n",
                          is_mandatory = False, is_numeric = False, default_value = None, print_param = True)

    add_parameter("save", "Save guid and pkey configurations of specific device or pci device.\n" \
     "                                              Please note that if file exist it will be overwriten.",
                          is_mandatory = False, is_numeric = False, default_value = None, print_param = True)

    add_parameter("restore", "Restore guid and pkey configurations of specific device or pci device", 
                          is_mandatory = False, is_numeric = False, default_value = None, print_param = True)

    add_flag("reset", "Operates on VFs only, Invalidates gid and pkeys table of the devices gid table.", print_param = True)

    add_flag("verify_guids", "verify that guid was updated as Required.", print_param = True)

    add_flag("reset-guid", "Operates on VFs only, Invalidates the default gid (index0) of the devices gid table.", print_param = True)

    add_flag("show-pkeys", "Dumps all pkey table at specified port and pci device.\n" \
     "                                              If no port is given all ports will be displayed.\n" \
     "                                              If pci-device is given, then the virtual pkey is shown,\n" \
     "                                              else physical port is displayed.", print_param = True)

    add_flag("show-guids", "Dumps the gid table of the physical port, or a specific device.\n" \
     "                                              If no port is given all ports will be displayed.", print_param = True)

    add_flag("show-mgids", "Dumps para-virtual state of all mgids (for all virtual devices)\n" \
     "                                              Cannot by specified in conjunction with pcidev.\n" \
     "                                              If no port is given all ports will be displayed.", print_param = True)

    add_flag("show-vfs", "Dumps all virtual function as a pci-device list, \n" \
     "                                              this parameter must be combined with device name", print_param = True)

    add_flag("short-output", "Each output in all show functions will be shown in new-line\n" \
    "                                              Mostly will be used when using scripts with this tool", print_param = True)


#######################################################################################
#######################################  MAIN  ########################################
#######################################################################################
if __name__ == "__main__":
    try: # For KeyboardInterrupt only
        if not is_xen_os():
            ERROR("This tool is only for Xen Dom-0 machines")
            sys.exit(1)
    
        # clean the database before the first using
        clean_database()
        define_params()
        init_params(sys.argv, TOOL_PARAMS)
    
        if is_opensm_down():
            ERROR("SM is down or not responding, please start opensm")
            sys.exit(1)
    
        for param_name in PARAM_CONVERT_LIST:
            if TOOL_PARAMS.has_key(param_name):
                TOOL_PARAMS[param_name] = TOOL_PARAMS[param_name].split(",")
        DEBUG_TRACE("TOOL_PARAMS %s" % str(TOOL_PARAMS))
        rc = verify_parameter(TOOL_PARAMS) or start_tool(TOOL_PARAMS)
    except KeyboardInterrupt:
        DATA_TRACE("A Keyboard Interrupt was pressed.. Exiting..")
        rc = 1

    if not (TOOL_PARAMS.has_key("short-output") and TOOL_PARAMS["short-output"] == True):
        if rc:
            ERROR("%s finished with error(s)" % APP_NAME)
        else:
            DATA_OK("%s finished successfully" % APP_NAME)

    sys.exit(rc)


