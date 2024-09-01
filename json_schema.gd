# Copyright (c) 2024 whogben
# SPDX-License-Identifier: MIT
# See LICENSE for details.
@icon("res://addons/gd_json_schema/_gd_json_schema_icon.svg")
@tool
class_name JSONSchema
## Provides basic validation of JSON Schemas against 
## https://json-schema.org/draft/2020-12/schema#
## See tag_validation_funcs for a list of supported tags.
## Works with dictionary instances as well as Godot Objects.



## Returns any validation issues with the instance. Invalid schemas will crash.
static func validate_schema(
	instance, 
	schema, 
	parent_schema:Dictionary = {}
) -> Array[String]:
	var issues:Array[String] = []
	
	for tag in schema:
		if tag not in tag_validation_funcs:
			push_warning('Unhandled tag "' + tag + '".')
			continue
		for _i in tag_validation_funcs[tag].call(instance, schema[tag], schema):
			issues.append(tag + ': ' + _i)
	
	return issues



## Associates JSON Schema tags with validation functions.
## Tags that aren't included are not validated and will raise a warning.
static var tag_validation_funcs = {
	"type": _validate_type,
	"properties": _validate_properties,
	"required": _validate_required,
	"anyOf": _validate_any_of,
	"allOf": _validate_all_of,
	"enum": _validate_enum,
	"minimum": _validate_minimum,
	"minimumExclusive": _validate_minimum.bind(true),
	"maximum": _validate_maximum,
	"maximumExclusive": _validate_maximum.bind(true),
	"minLength": _validate_min_length,
	"maxLength": _validate_max_length,
	'pattern': _validate_pattern,
	'format': _validate_format,
	'items': _validate_items,
	'additionalProperties': _validate_additional_properties,
	'not': _validate_not}

## Associates JSON Schema "format" tag values with functions that return true
## if valid. These are not perfect valdiators - they err on the pemissive side.
static var format_validators = {
	'date-time': _is_valid_date_time,
	'date': _is_valid_date,
	'time': _is_valid_time,
	'duration': _is_valid_duration,
	'email': _is_valid_email,
	'idn-email': _is_valid_idn_email,
	'hostname': _is_valid_hostname,
	'idn-hostname': _is_valid_idn_hostname,
	'ipv4': _is_valid_ipv4,
	'ipv6': _is_valid_ipv6,
	'uri': _is_valid_uri,
	'uri-reference': _is_valid_uri_reference,
	'iri': _is_valid_iri,
	'iri-reference': _is_valid_iri_reference,
	'uuid': _is_valid_uuid,
	'uri-template': _is_valid_uri_template,
	'json-pointer': _is_valid_json_pointer,
	'relative-json-pointer': _is_valid_relative_json_pointer,
	'regex': _is_valid_regex}

## Associates JSON Schema types with compatible Godot Variant.Type constants
const compatible_types = {
	"null": [TYPE_NIL],
	"boolean": [TYPE_BOOL],
	"integer": [TYPE_INT, TYPE_FLOAT],
	"number": [TYPE_FLOAT, TYPE_INT],
	"string": [TYPE_STRING, TYPE_STRING_NAME],
	"object": [TYPE_DICTIONARY, TYPE_OBJECT],
	"array": [
		TYPE_ARRAY,
		TYPE_PACKED_BYTE_ARRAY,
		TYPE_PACKED_COLOR_ARRAY,
		TYPE_PACKED_FLOAT32_ARRAY,
		TYPE_PACKED_FLOAT64_ARRAY,
		TYPE_PACKED_INT32_ARRAY,
		TYPE_PACKED_INT64_ARRAY,
		TYPE_PACKED_STRING_ARRAY,
		TYPE_PACKED_VECTOR2_ARRAY,
		TYPE_PACKED_VECTOR3_ARRAY,
		TYPE_PACKED_VECTOR4_ARRAY],}



static func _validate_type(
	instance,
	expected_type:String, 
	parent_schema:Dictionary = {}
) -> Array[String]:
	if typeof(instance) not in compatible_types[expected_type]:
		return ['type (%d) is not a "%s" (%s)' % [typeof(instance),
			expected_type, ', '.join(compatible_types[expected_type])]]
	return []

static func _validate_properties(
	instance, 
	properties:Dictionary, 
	parent_schema:Dictionary = {}
) -> Array[String]:
	var issues:Array[String] = _validate_type(instance, "object")
	if issues: return issues
	for key in properties:
		if key in instance:
			issues.append_array(
				validate_schema(instance.get(key), properties[key]))
	return issues

static func _validate_required(
	instance,
	required:Array, 
	parent_schema:Dictionary = {}
) -> Array[String]:
	var issues:Array[String] = _validate_type(instance, "object")
	if issues: return issues
	for property in required:
		if property not in instance:
			issues.append('missing required property "' + property + '".')
	return issues

static func _validate_any_of(
	instance, 
	any_of_schemas:Array, 
	parent_schema:Dictionary = {}
) -> Array[String]:
	var issues:Array[String] = []
	for schema in any_of_schemas:
		var _issues = validate_schema(instance, schema, parent_schema)
		if _issues: issues.append_array(_issues)
		else: return []
	return issues

static func _validate_all_of(
	instance, 
	all_of_schemas:Array, 
	parent_schema:Dictionary = {}
) -> Array[String]:
	var issues:Array[String] = []
	for schema in all_of_schemas:
		issues.append_array(validate_schema(instance, schema, parent_schema))
	return issues

static func _validate_enum(
	instance, 
	enumvalues:Array, 
	parent_schema:Dictionary = {}
) -> Array[String]:
	if instance in enumvalues: return []
	return ['value is not in enums.']

static func _validate_minimum(
	instance, 
	minimum,
	parent_schema:Dictionary = {},
	is_exclusive = false
) -> Array[String]:
	var issues:Array[String] = _validate_type(instance, "number")
	if issues: return issues
	if not is_exclusive and instance < minimum:
		return ['value (%d) < minimum (%d).' % [instance, minimum]]
	elif is_exclusive and instance <= minimum:
		return ['value (%d) <= minimumExclusive (%d).' % [instance, minimum]]
	return []

static func _validate_maximum(
	instance, 
	maximum,
	parent_schema:Dictionary = {},
	is_exclusive = false
) -> Array[String]:
	var issues:Array[String] = _validate_type(instance, "number")
	if issues: return issues
	if not is_exclusive and instance > maximum:
		return ['value (%d) > maximum (%d).' % [instance, maximum]]
	elif is_exclusive and instance >= maximum:
		return ['value (%d) >= maximumExclusive (%d).' % [instance, maximum]]
	return []

static func _validate_min_length(
	instance,
	min_length, 
	parent_schema:Dictionary = {}
) -> Array[String]:
	var issues:Array[String] = _validate_type(instance, "string")
	if issues: return issues
	if len(instance) < min_length:
		return ['length (%d) < minLength (%d).' % [len(instance), min_length]]
	return []

static func _validate_max_length(
	instance,
	max_length, 
	parent_schema:Dictionary = {}
) -> Array[String]:
	var issues:Array[String] = _validate_type(instance, "string")
	if issues: return issues
	if len(instance) > max_length:
		return ['length (%d) > maxLength (%d).' % [len(instance), max_length]]
	return []

static func _validate_pattern(
	instance,
	pattern, 
	parent_schema:Dictionary = {}
) -> Array[String]:
	var issues:Array[String] = _validate_type(instance, "string")
	if issues: return issues
	var re = RegEx.new()
	re.compile(pattern)
	if not re.search(instance):
		return ['does not match pattern (%s).' % pattern]
	return issues

static func _validate_format(
	instance, 
	format, 
	parent_schema:Dictionary = {}
) -> Array[String]:
	var issues:Array[String] = _validate_type(instance, "string")
	if not format_validators[format].call(instance):
		return ['not a valid ' + format]
	return []

static func _validate_items(
	instance, 
	items_schema, 
	parent_schema:Dictionary = {}
) -> Array[String]:
	var issues:Array[String] = _validate_type(instance, "array")
	for item in instance:
		issues.append_array(validate_schema(item, items_schema))
	return []

static func _validate_additional_properties(
	instance, 
	additional_properties, 
	parent_schema:Dictionary = {}
) -> Array[String]:
	if typeof(instance) == TYPE_OBJECT: return []
	if typeof(additional_properties) == TYPE_BOOL and additional_properties:
		return []
	var issues:Array[String] = _validate_type(instance, "object")
	if issues: return issues
	var defined_properties = parent_schema.get('properties', {}).keys()
	for prop in instance:
		if not prop in defined_properties:
			if typeof(additional_properties) == TYPE_DICTIONARY:
				issues.append_array(
					validate_schema(instance[prop], additional_properties))
			elif additional_properties == false:
				issues.append('additional property "%s" not allowed' % prop)
	return issues

static func _validate_not(
	instance, 
	not_schema, 
	parent_schema:Dictionary = {}
) -> Array[String]:
	if len(validate_schema(instance, not_schema, parent_schema)) > 0: 
		return [] # No error if it violates the "not" schema
	else:
		return ['instance violates "not" schema (should be invalid).']

static func _is_valid_date_time(instance: String) -> bool:
	return _regex(instance, "^(\\d{4}-(0[1-9]|1[0-2])-(0[1-9]|[12]\\d|3[01])T" +
		"([01]\\d|2[0-3]):[0-5]\\d:[0-5]\\d(?:\\.\\d+)?(?:Z|[+-](?:0\\d|1[0-4" +
		"]):[0-5]\\d)?)$")

static func _is_valid_date(instance: String) -> bool:
	return _regex(instance, "^(\\d{4}-(0[1-9]|1[0-2])-(0[1-9]|[12]\\d|3[01]))$")

static func _is_valid_time(instance: String) -> bool:
	return _regex(instance, "^([01]\\d|2[0-3]):[0-5]\\d:[0-5]\\d(?:\\.\\d+)?$")

static func _is_valid_duration(instance: String) -> bool:
	return _regex(instance, "^P(?:\\d+Y)?(?:\\d+M)?(?:\\d+W)?(?:\\d+D)?(?:T(?" +
		":\\d+H)?(?:\\d+M)?(?:\\d+S)?)?$" )

static func _is_valid_email(instance: String) -> bool:
	return _regex(instance, "^[a-zA-Z0-9.!#$%&'*+/=?^_`{|}~-]+@[a-zA-Z0-9](?:" +
		"[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(?:\\.[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61" +
		"}[a-zA-Z0-9])?)*$")

static func _is_valid_idn_email(instance: String) -> bool:
	return _regex(instance, "^[a-zA-Z0-9.!#$%&'*+/=?^_`{|}~-]+@[\\p{L}\\d-]+(" +
		"?:\\.[\\p{L}\\d-]+)*\\.[\\p{L}]{2,}$")

static func _is_valid_hostname(instance: String) -> bool:
	return _regex(instance, "^(?!-)(([a-zA-Z0-9-_]|xn--)?(?:[a-zA-Z0-9-_]{0,6" +
		"1}[a-zA-Z0-9-_])?)(\\.([a-zA-Z0-9-_]|xn--)?(?:[a-zA-Z0-9-_]{0,61}[a-" +
		"zA-Z0-9-_])?)*$")

static func _is_valid_idn_hostname(instance: String) -> bool:
	return _regex(instance, "^(?!-)([a-zA-Z0-9_-]|xn--)(?:[a-zA-Z0-9_-]{0,61}" +
	"[a-zA-Z0-9_-])?(\\.([a-zA-Z0-9_-]|xn--)(?:[a-zA-Z0-9_-]{0,61}[a-zA-Z0-9_" +
	"-])?)*$")

static func _is_valid_ipv4(instance: String) -> bool:
	return _regex(instance, "^(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\\.(25[0-" +
	"5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?" +
	")\\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$")

static func _is_valid_ipv6(instance: String) -> bool:
	return _regex(instance, "^(([0-9a-fA-F]{1,4}:){7,7}[0-9a-fA-F]{1,4}|([0-9" +
	"a-fA-F]{1,4}:){1,7}:|([0-9a-fA-F]{1,4}:){1,6}:[0-9a-fA-F]{1,4}|([0-9a-fA" +
	"-F]{1,4}:){1,5}(:[0-9a-fA-F]{1,4}){1,2}|([0-9a-fA-F]{1,4}:){1,4}(:[0-9a-" +
	"fA-F]{1,4}){1,3}|([0-9a-fA-F]{1,4}:){1,3}(:[0-9a-fA-F]{1,4}){1,4}|([0-9a" +
	"-fA-F]{1,4}:){1,2}(:[0-9a-fA-F]{1,4}){1,5}|[0-9a-fA-F]{1,4}:(:[0-9a-fA-F" +
	"]{1,4}){1,6}|:(:[0-9a-fA-F]{1,4}){1,7}|:|(?:(?:ffff:)?(?:25[0-5]|2[0-4]" +
	"\\d|[01]?\\d\\d?)\\.){3}(?:25[0-5]|2[0-4]\\d|[01]?\\d\\d?))$")

static func _is_valid_uri(instance: String) -> bool:
	return _regex(instance, "^(?:([a-zA-Z][a-zA-Z0-9+.-]*):)?(\\/\\/)?([^\\/" +
		"\\?#]*)(\\?[^#]*)?(#.*)?$")

static func _is_valid_uri_reference(instance: String) -> bool:
	return _regex(instance, "^(?:([a-zA-Z][a-zA-Z0-9+.-]*):)?(\\/\\/)?([^\\/" +
		"\\?#]*)(\\?[^#]*)?(#.*)?$")

static func _is_valid_iri(instance: String) -> bool:
	return _regex(instance, "^(?:([a-zA-Z][a-zA-Z0-9+.-]*):)?(\\/\\/)?(?:([^" +
		"\\/\\?#\\s]*))(\\?[^#\\s]*)?(#\\S*)?$")

static func _is_valid_iri_reference(instance: String) -> bool:
	return _regex(instance, "^(?:([a-zA-Z][a-zA-Z0-9+.-]*):)?(\\/\\/)?(?:([^" +
		"\\/\\?#\\s]*))(\\?[^#\\s]*)?(#\\S*)?$")

static func _is_valid_uuid(instance: String) -> bool:
	return _regex(instance, "^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[1-5][0-9a-fA-F]{" +
		"3}-[89abAB][0-9a-fA-F]{3}-[0-9a-fA-F]{12}$")

static func _is_valid_uri_template(instance: String) -> bool:
	return _regex(instance, "^\\{([a-zA-Z0-9_%]+)(?:\\|([a-zA-Z0-9_%]+))?\\}$")

static func _is_valid_json_pointer(instance: String) -> bool:
	return _regex(instance, "^(\\/((?:~[01]|[^~\\/])*(?:~[01]|[^~\\/]))*)*$")

static func _is_valid_relative_json_pointer(instance: String) -> bool:
	return _regex(instance, "^(?:0|[1-9][0-9]*)(?:#|(?:\\/(?:~[01]|[^~\\/])*(" +
		"?:~[01]|[^~\\/]))*)$")

static func _is_valid_regex(instance: String) -> bool:
	return _regex(instance, "^(?:[^\\n\\\\]|\\\\.)*$")

# always returns true, used to stub unimplemented format validators
static func _is_valid_dummy(instance) -> bool:
	return true

static var _cached_regices:Dictionary

## Performs a regex and caches the resulting RegEx object for reuse
static func _regex(instance:String, regexstr:String) -> bool:
	if not regexstr in _cached_regices:
		_cached_regices[regexstr] = RegEx.new()
		var err = _cached_regices[regexstr].compile(regexstr)
		assert(err == OK)
	return _cached_regices[regexstr].search(instance) != null
