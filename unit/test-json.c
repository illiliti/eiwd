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

/*
 * Tests that the token bounds checking works.
 */
static void test_json_larger_object(const void *data)
{
	char json[] = "{\"test1\":\"tester1\","
			"\"test2\":\"tester2\","
			"\"test3\":\"tester3\","
			"\"test4\":\"tester4\","
			"\"test5\":\"tester5\","
			"\"test6\":\"tester6\","
			"\"test7\":\"tester7\","
			"\"test8\":\"tester8\","
			"\"test9\":\"tester9\","
			"\"test10\":\"tester10\","
			"\"test11\":\"tester11\","
			"\"test12\":\"tester12\","
			"\"test13\":\"tester13\"}";

	struct json_iter iter;
	struct json_contents *c = json_contents_new(json, strlen(json));

	json_iter_init(&iter, c);
	assert(json_iter_parse(&iter,
				JSON_MANDATORY("test13", JSON_STRING, NULL),
				JSON_UNDEFINED));
	json_contents_free(c);
}

static void check_primitives(struct json_iter *i, struct json_iter *ui,
				struct json_iter *t, struct json_iter *f,
				struct json_iter *null, struct json_iter *obj)
{

	int i_val;
	unsigned int ui_val;
	bool b_val;

	assert(json_iter_is_valid(i));
	assert(!json_iter_get_uint(i, NULL));
	assert(!json_iter_get_boolean(i, NULL));
	assert(!json_iter_get_null(i));
	assert(!json_iter_next(i));
	assert(json_iter_get_int(i, &i_val));
	assert(i_val == -10);

	assert(json_iter_is_valid(ui));
	assert(!json_iter_get_boolean(ui, NULL));
	assert(!json_iter_get_null(ui));
	assert(!json_iter_next(ui));
	assert(json_iter_get_int(ui, &i_val));
	assert(json_iter_get_uint(ui, &ui_val));
	assert(i_val == 10 && ui_val == 10);

	assert(json_iter_is_valid(t));
	assert(!json_iter_get_null(t));
	assert(!json_iter_get_int(t, NULL));
	assert(!json_iter_get_uint(t, NULL));
	assert(!json_iter_next(t));
	assert(json_iter_get_boolean(t, &b_val));
	assert(b_val == true);

	assert(json_iter_is_valid(f));
	assert(!json_iter_get_null(f));
	assert(!json_iter_get_int(f, NULL));
	assert(!json_iter_get_uint(f, NULL));
	assert(!json_iter_next(f));
	assert(json_iter_get_boolean(f, &b_val));
	assert(b_val == false);

	assert(json_iter_is_valid(null));
	assert(!json_iter_get_int(null, NULL));
	assert(!json_iter_get_uint(null, NULL));
	assert(!json_iter_get_boolean(null, NULL));
	assert(!json_iter_next(null));
	assert(json_iter_get_null(null));

	if (obj) {
		assert(json_iter_is_valid(obj));
		assert(!json_iter_next(obj));
		assert(json_iter_parse(obj,
			JSON_MANDATORY("null_val", JSON_PRIMITIVE, null),
			JSON_MANDATORY("false_val", JSON_PRIMITIVE, f),
			JSON_MANDATORY("true_val", JSON_PRIMITIVE, t),
			JSON_MANDATORY("int_val", JSON_PRIMITIVE, i),
			JSON_MANDATORY("uint_val", JSON_PRIMITIVE, ui),
			JSON_UNDEFINED));

		check_primitives(i, ui, t, f, null, NULL);
	}
}

static void test_json_primitives(const void *data)
{
	char json[] = "{\"int_val\": -10,"
			"\"uint_val\": 10,"
			"\"true_val\": true,"
			"\"false_val\": false,"
			"\"null_val\": null,"
			"\"obj_val\":{"
				"\"int_val\": -10,"
				"\"uint_val\": 10,"
				"\"true_val\": true,"
				"\"false_val\": false,"
				"\"null_val\": null}}";
	struct json_contents *c = json_contents_new(json, strlen(json));
	struct json_iter outer, inner, null, f, t, i, ui;
	struct json_iter not_found;

	json_iter_init(&outer, c);
	assert(json_iter_parse(&outer,
			JSON_MANDATORY("obj_val", JSON_OBJECT, &inner),
			JSON_MANDATORY("null_val", JSON_PRIMITIVE, &null),
			JSON_MANDATORY("false_val", JSON_PRIMITIVE, &f),
			JSON_MANDATORY("true_val", JSON_PRIMITIVE, &t),
			JSON_MANDATORY("int_val", JSON_PRIMITIVE, &i),
			JSON_MANDATORY("uint_val", JSON_PRIMITIVE, &ui),
			JSON_OPTIONAL("not_found", JSON_PRIMITIVE, &not_found),
			JSON_UNDEFINED));

	assert(!json_iter_is_valid(&not_found));

	check_primitives(&i, &ui, &t, &f, &null, &inner);

	json_contents_free(c);
}

static void test_json_arrays(const void *data)
{
	unsigned int ui;
	int i;
	bool b;
	int count;
	char json[] = "{\"uint_array\":[1, 2, 3, 4, 5, 6],"
			"\"int_array\":[-1, -2, -3, -4, -5, -6],"
			"\"bool_array\":[true, false, true, false],"
			"\"null_array\":[null, null, null, null],"
			"\"obj_array\":[{}, {\"key\":\"value\", \"key2\":\"value2\"}],"
			"\"mixed_array\":[1, -1, true, false, null, \"string\"]}";

	struct json_iter iter;
	struct json_iter i_array, ui_array, b_array, n_array,
				m_array, obj_array;
	struct json_contents *c = json_contents_new(json, strlen(json));

	json_iter_init(&iter, c);
	assert(json_iter_parse(&iter,
			JSON_MANDATORY("mixed_array", JSON_ARRAY, &m_array),
			JSON_MANDATORY("null_array", JSON_ARRAY, &n_array),
			JSON_MANDATORY("bool_array", JSON_ARRAY, &b_array),
			JSON_MANDATORY("int_array", JSON_ARRAY, &i_array),
			JSON_MANDATORY("uint_array", JSON_ARRAY, &ui_array),
			JSON_MANDATORY("obj_array", JSON_ARRAY, &obj_array),
			JSON_UNDEFINED));

	count = 1;

	while (json_iter_next(&ui_array)) {
		assert(json_iter_get_type(&ui_array) == JSON_PRIMITIVE);
		assert(!json_iter_parse(&ui_array, JSON_UNDEFINED));
		assert(json_iter_get_uint(&ui_array, &ui));
		assert(ui == (unsigned int) count);
		count++;
	}

	count = -1;

	while (json_iter_next(&i_array)) {
		assert(json_iter_get_type(&i_array) == JSON_PRIMITIVE);
		assert(!json_iter_parse(&i_array, JSON_UNDEFINED));
		assert(json_iter_get_int(&i_array, &i));
		assert(i == count);
		count--;
	}

	count = 0;

	while (json_iter_next(&b_array)) {
		assert(json_iter_get_type(&b_array) == JSON_PRIMITIVE);
		assert(!json_iter_parse(&b_array, JSON_UNDEFINED));
		assert(json_iter_get_boolean(&b_array, &b));
		assert(b == count % 2 ? false : true);
		count++;
	}

	count = 0;

	while (json_iter_next(&n_array)) {
		assert(json_iter_get_type(&n_array) == JSON_PRIMITIVE);
		assert(!json_iter_parse(&n_array, JSON_UNDEFINED));
		assert(json_iter_get_null(&n_array));
		count++;
	}

	assert(count == 4);

	count = 0;

	while (json_iter_next(&m_array)) {
		_auto_(l_free) char *str = NULL;

		switch (count) {
		case 0:
			assert(json_iter_get_type(&m_array) == JSON_PRIMITIVE);
			assert(json_iter_get_uint(&m_array, &ui));
			assert(ui == 1);
			break;
		case 1:
			assert(json_iter_get_type(&m_array) == JSON_PRIMITIVE);
			assert(json_iter_get_int(&m_array, &i));
			assert(i == -1);
			break;
		case 2:
		case 3:
			assert(json_iter_get_type(&m_array) == JSON_PRIMITIVE);
			assert(json_iter_get_boolean(&m_array, &b));
			assert(b == count % 2 ? false : true);
			break;
		case 4:
			assert(json_iter_get_type(&m_array) == JSON_PRIMITIVE);
			assert(json_iter_get_null(&m_array));
			break;
		case 5:
			assert(json_iter_get_type(&m_array) == JSON_STRING);
			assert(json_iter_get_string(&m_array, &str));
			assert(!strcmp(str, "string"));
			break;
		}

		count++;
	}

	count = 0;

	assert(!json_iter_parse(&obj_array, JSON_UNDEFINED));

	while (json_iter_next(&obj_array)) {
		struct json_iter object;

		assert(json_iter_get_type(&obj_array) == JSON_OBJECT);
		assert(json_iter_get_container(&obj_array, &object));

		switch (count) {
		case 0:
			assert(json_iter_parse(&object, JSON_UNDEFINED));
			break;
		case 1:
			assert(json_iter_parse(&object,
				JSON_MANDATORY("key", JSON_STRING, NULL),
				JSON_UNDEFINED));
			break;
		}

		count++;
	}

	assert(count == 2);

	json_contents_free(c);
}

static void test_json_nested_arrays(const void *data)
{
	char json[] = "{\"array\":[[], {}, [1, 2], {\"key\":\"value\"}, [\"one\",\"two\"]]}";
	int count = 0;
	struct json_iter iter;
	struct json_iter array;
	struct json_iter inner;
	struct json_contents *c = json_contents_new(json, strlen(json));

	json_iter_init(&iter, c);
	assert(json_iter_parse(&iter,
			JSON_MANDATORY("array", JSON_ARRAY, &array),
			JSON_UNDEFINED));

	while (json_iter_next(&array)) {
		int count2 = 0;

		assert(json_iter_get_container(&array, &inner));

		while (json_iter_next(&inner)) {
			_auto_(l_free) char *str = NULL;

			switch (count) {
			case 0:
			case 1:
				assert(false);
				break;
			case 4:
				assert(json_iter_get_type(&inner) ==
							JSON_STRING);
				assert(json_iter_get_string(&inner, &str));

				if (count2 == 0)
					assert(!strcmp("one", str));
				else
					assert(!strcmp("two", str));

				break;
			}

			count2++;
		}

		switch (count) {
		case 0:
			assert(count2 == 0);
			break;
		case 1:
			assert(count2 == 0);
			break;
		case 2:
			assert(count2 == 2);
			break;
		case 3:
			assert(count2 == 0);
			break;
		case 4:
			assert(count2 == 2);
			break;
		default:
			break;
		}

		count++;
	}

	assert(count == 5);

	json_contents_free(c);
}

int main(int argc, char *argv[])
{
	l_test_init(&argc, &argv);

	l_test_add("json unicode", test_json_unicode, NULL);
	l_test_add("json escaped unicode", test_json_escaped_unicode, NULL);
	l_test_add("json nested objects", test_json, NULL);
	l_test_add("json empty objects", test_json_empty_objects, NULL);
	l_test_add("json parse out of order", test_json_out_of_order, NULL);
	l_test_add("json larger object", test_json_larger_object, NULL);
	l_test_add("json test primitives", test_json_primitives, NULL);
	l_test_add("json test arrays", test_json_arrays, NULL);
	l_test_add("json test nested arrays", test_json_nested_arrays, NULL);

	return l_test_run();
}
