/*
 *
 *  Wireless daemon for Linux
 *
 *  Copyright (C) 2021  Intel Corporation. All rights reserved.
 *
 *  This library is free software; you can redistribute it and/or
 *  modify it under the terms of the GNU Lesser General Public
 *  License as published by the Free Software Foundation; either
 *  version 2.1 of the License, or (at your option) any later version.
 *
 *  This library is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 *  Lesser General Public License for more details.
 *
 *  You should have received a copy of the GNU Lesser General Public
 *  License along with this library; if not, write to the Free Software
 *  Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA  02110-1301  USA
 *
 */

struct json_iter;

/*
 * Identical to JSMN types
 */
enum json_type {
	JSON_UNDEFINED = 0,
	JSON_OBJECT = 1 << 0,
	JSON_ARRAY = 1 << 1,
	JSON_STRING = 1 << 2,
	JSON_PRIMITIVE = 1 << 3,
};

enum json_flag {
	JSON_FLAG_MANDATORY = 1,
	JSON_FLAG_OPTIONAL = 2,
};

struct json_iter {
	struct json_contents *contents;
	int start;
	int count;
	int current;
};

#define JSON_MANDATORY(key, type, out) \
	(type), (key), (out), JSON_FLAG_MANDATORY

#define JSON_OPTIONAL(key, type, out) \
	(type), (key), (out), JSON_FLAG_OPTIONAL

#define json_iter_is_valid(iter) ((iter)->start != -1)

struct json_contents *json_contents_new(const char *json, size_t json_len);
void json_contents_free(struct json_contents *c);

void json_iter_init(struct json_iter *iter, struct json_contents *c);

/*
 * Parse an arbitrary number of key/value pairs from a JSON iterator. Initially
 * a new JSON contents object should be created with json_contents_new() and,
 * when done, freed with json_contents_free.
 *
 * Iterators can be initialized with the json_contents object. Nested object
 * iterators are also parsed with this function.
 *
 * Arguments should be specified using JSON_MANDATORY or JSON_OPTIONAL:
 *
 * r = json_iter_parse(iter, JSON_MANDATORY("mykey", JSON_STRING, &strvalue),
 *			JSON_OPTIONAL("optkey", JSON_STRING, &optvalue),
 *			JSON_UNDEFINED);
 *
 * String values should be of type char ** and must be freed
 * Object values should be of type struct json_iter *
 * Primitive types (numbers, booleans, null) should be of type
 *		struct json_iter *. This is to allow the caller to distinguish
 *		between the actual value type after parsing using a getter for
 *		the expected type (get_uint/get_int/get_boolean etc.). In
 *		addition this lets the caller use JSON_OPTIONAL and check post
 *		json_iter_parse if the iterator is valid (json_iter_is_valid).
 *
 * No other types are supported at this time, and json_iter_parse will fail if
 * other types are encountered.
 *
 * JSON_OPTIONAL string values will point to NULL if not found
 * JSON_OPTIONAL objects/primitives can be checked with json_object_is_valid.
 */
bool json_iter_parse(struct json_iter *iter, enum json_type type, ...);

bool json_iter_get_int(struct json_iter *iter, int *i);
bool json_iter_get_uint(struct json_iter *iter, unsigned int *i);
bool json_iter_get_boolean(struct json_iter *iter, bool *b);
bool json_iter_get_null(struct json_iter *iter);
bool json_iter_get_container(struct json_iter *iter,
				struct json_iter *container);
bool json_iter_get_string(struct json_iter *iter, char **s);

enum json_type json_iter_get_type(struct json_iter *iter);
bool json_iter_next(struct json_iter *iter);
