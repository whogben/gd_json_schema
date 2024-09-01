# GD JSON Schema
A addon for Godot to validate objects or dictionaries with JSON Schemas.
- Supporting a minimal subset of JSONSchema tags - see the [tag_validation_funcs](json_schema.gd) list.
- Can validate Objects or Dictionaries
- Implemented in GDScript.

# How to Use

1. Make a schema
```gdscript
var test_schema = {
	"type": "object",
	"properties": {
		"name": { "type": "string" },
		"age": { "type": "integer" }
	},
	"not": {
		"properties": {
			"name": { "pattern": "^J.*" } # Name should NOT start with "J"
		}
	}
}
```

2. Test some objects
```gdscript
var valid_obj = {"name": "Alice", "age": 30}

var invalid_obj = {"name": "John", "age": 25}

print('\nTesting invalid instance:')
var issues = JSONSchema.validate_schema(invalid_obj, test_schema)
for issue in issues:
  print('\t- ' + issue)
	
print('\nTesting valid instance:')
issues = JSONSchema.validate_schema(valid_obj, test_schema)
for issue in issues:
  print('\t- ' + issue)
```

Output:
```
Testing invalid instance:
	- not: instance violates "not" schema (should be invalid).

Testing valid instance:
```

# How to Add More Tags

1. Create a new validation function following this format:
```gdscript
func _validate_some_other_tag(instance, some_other_tag, parent:Dictionary = {}) -> Array[String]:
	# TODO: fill in your validation logic here
	return []
```
2. Add your validation function to the tag_validation_funcs dictionary:
```gdscript
static var tag_validation_funcs = {
	"type": _validate_type,
	"properties": _validate_properties,
	<..>
	'additionalProperties': _validate_additional_properties,
	'not': _validate_not,
	'someOtherTag':_validate_some_other_tag
}
```
3. You're done - don't forget to test it.

# Other Notes
- AI wrote and reviewed the regexes used for format validation, they passed 1 test each but you might consider tightening them up if they're crucial to your use case. The AI was instructed to err on the permissive side.
- I wrote this because I need it, which is why it only features the tags I need right now, if you add more tags please submit a pull request and I'll merge them in.
