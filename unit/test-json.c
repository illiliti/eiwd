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

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <stdio.h>
#include <assert.h>

#include <ell/ell.h>

#include "src/json.h"
#include "ell/useful.h"

struct json_contents;


/*
 * Object:
 * { "test": "<smile emoji>" }
 */
static void test_json_unicode(const void *data)
{
	struct json_iter iter;
	_auto_(l_free)char *v;
	uint8_t expected[] = { 0xF0, 0x9F, 0x98, 0x80, 0 };

	uint8_t s[] = { '{', '"', 't', 'e', 's', 't', '"', ':',
				'"', 0xf0, 0x9f, 0x98, 0x80, '"', '}', 0 };
	struct json_contents *c = json_contents_new((const char *)s, sizeof(s));

	json_iter_init(&iter, c);
	assert(json_iter_parse(&iter, JSON_MANDATORY("test", JSON_STRING, &v),
				JSON_UNDEFINED));

	assert(!strcmp(v, (char *)expected));

	json_contents_free(c);
}

static void test_json_escaped_unicode(const void *data)
{
	struct json_iter iter;
	_auto_(l_free)char *v;
	char *s = "{\"test\":\"\\uD8F0\"}";
	char expected[] = "\\uD8F0";
	struct json_contents *c = json_contents_new(s, strlen(s));

	json_iter_init(&iter, c);
	assert(json_iter_parse(&iter, JSON_MANDATORY("test", JSON_STRING, &v),
				JSON_UNDEFINED));

	assert(!strcmp(v, expected));

	json_contents_free(c);
}

/*
 * Tests that unsupported types will not parse
 */
static void test_json_unsupported_types(const void *data)
{
	/*
	 * Valid JSON objects but currently unsupported types
	 */
	char arrays[] = "{\"test\":[1, 2, 3, 4]}";
	char integers[] = "{\"test\": 10 }";
	char bools[] = "{\"test\": true}";

	struct json_iter iter;
	struct json_contents *c = json_contents_new(arrays, strlen(arrays));

	json_iter_init(&iter, c);
	assert(!json_iter_parse(&iter,
				JSON_MANDATORY("test", JSON_ARRAY, NULL),
				JSON_UNDEFINED));
	json_contents_free(c);

	c = json_contents_new(integers, strlen(integers));
	json_iter_init(&iter, c);
	assert(!json_iter_parse(&iter,
				JSON_MANDATORY("test", JSON_PRIMITIVE, NULL),
				JSON_UNDEFINED));
	json_contents_free(c);

	c = json_contents_new(bools, strlen(bools));
	json_iter_init(&iter, c);
	assert(!json_iter_parse(&iter,
				JSON_MANDATORY("test", JSON_PRIMITIVE, NULL),
				JSON_UNDEFINED));
	json_contents_free(c);
}

/*
 * Basic test string values and nested objects
 */
static void test_json(const void *data)
{
	char json[] = "{\"wi-fi_tech\":\"infra\","
			"\"discovery\":"
				"{\"ssid\":\"somessid\"},"
			"\"cred\":"
				"{\"akm\":\"psk\","
				"\"pass\":\"somepassphrase\"}}";
	_auto_(l_free)char *tech;
	_auto_(l_free)char *ssid;
	_auto_(l_free)char *akm;
	_auto_(l_free)char *pass;
	_auto_(l_free)char *opt_not_found;
	struct json_iter objnotfound;
	struct json_iter discovery;
	struct json_iter cred;
	struct json_iter iter;
	struct json_contents *c = json_contents_new(json, strlen(json));

	json_iter_init(&iter, c);
	assert(json_iter_parse(&iter,
			JSON_MANDATORY("wi-fi_tech", JSON_STRING, &tech),
			JSON_MANDATORY("discovery", JSON_OBJECT, &discovery),
			JSON_MANDATORY("cred", JSON_OBJECT, &cred),
			JSON_OPTIONAL("notfound", JSON_STRING, &opt_not_found),
			JSON_OPTIONAL("objnotfound", JSON_OBJECT, &objnotfound),
			JSON_UNDEFINED));

	assert(opt_not_found == NULL);
	assert(!json_iter_is_valid(&objnotfound));

	assert(!strcmp(tech, "infra"));

	assert(json_iter_parse(&discovery,
			JSON_MANDATORY("ssid", JSON_STRING, &ssid),
			JSON_UNDEFINED));

	assert(!strcmp(ssid, "somessid"));

	assert(json_iter_parse(&cred,
			JSON_MANDATORY("akm", JSON_STRING, &akm),
			JSON_MANDATORY("pass", JSON_STRING, &pass),
			JSON_UNDEFINED));
	assert(!strcmp(akm, "psk"));
	assert(!strcmp(pass, "somepassphrase"));

	json_contents_free(c);
}

/*
 * Tests empty objects parse successfully
 */
static void test_json_empty_objects(const void *data)
{
	char empty[] = "{}";
	char nested_empty[] = "{\"empty\":{}}";
	struct json_iter nested_iter;
	struct json_iter iter;
	struct json_contents *c = json_contents_new(empty, strlen(empty));

	json_iter_init(&iter, c);
	assert(json_iter_parse(&iter, JSON_UNDEFINED));

	assert(json_iter_parse(&iter,
				JSON_OPTIONAL("optional", JSON_OBJECT, NULL),
				JSON_UNDEFINED));

	assert(!json_iter_parse(&iter,
				JSON_MANDATORY("optional", JSON_OBJECT, NULL),
				JSON_UNDEFINED));
	json_contents_free(c);

	c = json_contents_new(nested_empty, strlen(nested_empty));
	json_iter_init(&iter, c);
	assert(json_iter_parse(&iter,
			JSON_MANDATORY("empty", JSON_OBJECT, &nested_iter),
			JSON_UNDEFINED));
	assert(json_iter_parse(&nested_iter, JSON_UNDEFINED));
	assert(!json_iter_parse(&nested_iter,
				JSON_MANDATORY("mandatory", JSON_OBJECT, NULL),
				JSON_UNDEFINED));
	json_contents_free(c);
}

/*
 * Tests that expected key/values can be provided in an order different than
 * they appear in the JSON string.
 */
static void test_json_out_of_order(const void *data)
{
	char object[] = "{\"key1\":{},\"key2\":\"val2\",\"key3\":\"val3\"}";
	struct json_iter iter;
	struct json_contents *c = json_contents_new(object, strlen(object));

	json_iter_init(&iter, c);
	assert(json_iter_parse(&iter,
				JSON_OPTIONAL("nonexist1", JSON_STRING, NULL),
				JSON_MANDATORY("key3", JSON_STRING, NULL),
				JSON_MANDATORY("key2", JSON_STRING, NULL),
				JSON_OPTIONAL("nonexist2", JSON_OBJECT, NULL),
				JSON_MANDATORY("key1", JSON_OBJECT, NULL),
				JSON_UNDEFINED));
	json_contents_free(c);
}

int main(int argc, char *argv[])
{
	l_test_init(&argc, &argv);

	l_test_add("json unicode", test_json_unicode, NULL);
	l_test_add("json escaped unicode", test_json_escaped_unicode, NULL);
	l_test_add("json nested objects", test_json, NULL);
	l_test_add("json unsupported types", test_json_unsupported_types, NULL);
	l_test_add("json empty objects", test_json_empty_objects, NULL);
	l_test_add("json parse out of order", test_json_out_of_order, NULL);

	return l_test_run();
}
