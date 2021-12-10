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

#include <errno.h>

#include <ell/ell.h>

#include "src/json.h"

#include "shared/jsmn.h"

/* Max number of tokens supported. Increase if larger objects are expected */
#define JSON_DEFAULT_TOKENS 30

#define TOK_LEN(token) (token)->end - (token)->start
#define TOK_PTR(json, token) (void *)((json) + (token)->start)
#define TOK_TO_STR(json, token) \
({ \
	char *_tmp = l_malloc(TOK_LEN((token)) + 1); \
	memcpy(_tmp, TOK_PTR((json), (token)), TOK_LEN((token))); \
	_tmp[TOK_LEN((token))] = '\0'; \
	_tmp; \
})

#define ITER_END(iter) \
	(((iter)->contents->tokens + (iter)->start) + (iter)->count)

struct json_contents {
	const char *json;
	size_t json_len;
	jsmntok_t *tokens;
	int tokens_len;
	jsmn_parser *p;
};

static jsmntok_t *next_key_in_parent(struct json_iter *iter, jsmntok_t *current)
{
	int parent = current->parent;

	/* iterate the list and stop on the first token with the same parent */
	while (++current < ITER_END(iter)) {
		if (current->parent == parent)
			return current;
	}

	return NULL;
}

/*
 * 'object' is expected to be a value, so object - 1 is its key. Find
 * the next key who's parent matches the parent of object - 1. The
 * token preceeding this next key will mark the end of 'object'.
 */
static int find_object_tokens(struct json_iter *iter, jsmntok_t *object)
{
	jsmntok_t *next = next_key_in_parent(iter, object - 1);

	/* End of token list */
	if (!next)
		next = ITER_END(iter);

	return ((next - object) % sizeof(jsmntok_t)) - 1;
}

static void iter_recurse(struct json_iter *iter, jsmntok_t *object,
				struct json_iter *child)
{
	struct json_contents *c = iter->contents;

	child->contents = c;
	child->start = (object - c->tokens) % sizeof(jsmntok_t);
	child->count = find_object_tokens(iter, object);
}

struct json_contents *json_contents_new(const char *json, size_t json_len)
{
	struct json_contents *c = l_new(struct json_contents, 1);

	c->json = json;
	c->json_len = json_len;
	c->p = l_new(jsmn_parser, 1);
	c->tokens = l_new(jsmntok_t, JSON_DEFAULT_TOKENS);

	jsmn_init(c->p);
	c->tokens_len = jsmn_parse(c->p, c->json, c->json_len,
					c->tokens, JSON_DEFAULT_TOKENS);
	if (c->tokens_len < 0) {
		json_contents_free(c);
		return NULL;
	}

	return c;
}

void json_iter_init(struct json_iter *iter, struct json_contents *c)
{
	iter->contents = c;
	iter->start = 0;
	iter->count = c->tokens_len;
}

void json_contents_free(struct json_contents *c)
{
	l_free(c->p);
	l_free(c->tokens);
	l_free(c);
}

struct json_arg {
	enum json_type type;
	void *value;
	jsmntok_t *v;
};

static void push_arg(struct l_queue *q, enum json_type type,
			void *value, jsmntok_t *v)
{
	struct json_arg *arg = l_new(struct json_arg, 1);

	arg->type = type;
	arg->value = value;
	arg->v = v;

	l_queue_push_head(q, arg);
}

static void assign_arg(void *data, void *user_data)
{
	struct json_iter *iter = user_data;
	struct json_arg *arg = data;
	struct json_contents *c = iter->contents;
	char **sval;
	struct json_iter *oval;

	switch (arg->type) {
	case JSON_STRING:
		sval = arg->value;

		*sval = arg->v ? TOK_TO_STR(c->json, arg->v) : NULL;

		break;
	case JSON_OBJECT:
		oval = arg->value;

		if (!arg->v)
			oval->start = -1;
		else
			iter_recurse(iter, arg->v, oval);

		break;
	default:
		/* Types are verified earlier, this should never happen */
		return;
	}

	l_free(arg);
}

bool json_iter_parse(struct json_iter *iter, enum json_type type, ...)
{
	struct json_contents *c = iter->contents;
	va_list va;
	int i;
	int num = c->tokens->size;
	jsmntok_t *next;
	struct l_queue *args;

	if (iter->start == -1)
		return false;

	args = l_queue_new();

	va_start(va, type);

	while (true) {
		enum json_flag flag;
		char *key;
		void *value;
		jsmntok_t *v = NULL;
		void *ptr;
		size_t len;

		/* Check the type is supported before wasting any cycles */
		switch (type) {
		case JSON_UNDEFINED:
			goto done;
		case JSON_STRING:
		case JSON_OBJECT:
			break;
		default:
			goto error;
		}

		key = va_arg(va, char *);
		value = va_arg(va, void *);
		flag = va_arg(va, enum json_flag);

		/* First key */
		next = c->tokens + iter->start + 1;

		/* Iterate over this objects keys */
		for (i = 0; i < num; i++) {
			ptr = TOK_PTR(c->json, next);
			len = TOK_LEN(next);

			if (next + 1 > ITER_END(iter))
				goto error;

			if (strlen(key) == len && !memcmp(ptr, key, len)) {
				/* Key found but the wrong value type */
				if ((next + 1)->type != (jsmntype_t)type)
					goto error;

				v = next + 1;
				break;
			}

			next = next_key_in_parent(iter, next);
			if (!next)
				break;
		}

		if (flag == JSON_FLAG_MANDATORY && !v)
			goto error;

		/*
		 * Still push even if an optional value doesn't exist (!v) so
		 * the caller can check if it was found or not.
		 */
		if (value)
			push_arg(args, type, value, v);

		type = va_arg(va, enum json_type);
	}

done:
	va_end(va);

	l_queue_foreach(args, assign_arg, iter);
	l_queue_destroy(args, NULL);

	return true;

error:
	l_queue_destroy(args, l_free);
	return false;
}
