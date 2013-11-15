/*
 * This file is part of ltrace.
 * Copyright (C) 2011,2012,2013 Petr Machata, Red Hat Inc.
 * Copyright (C) 1998,2004,2007,2008,2009 Juan Cespedes
 * Copyright (C) 2006 Steve Fink
 * Copyright (C) 2006 Ian Wienand
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License as
 * published by the Free Software Foundation; either version 2 of the
 * License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA
 * 02110-1301 USA
 */

#include <assert.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include "printf.h"
#include "abi.h"
#include "expr.h"
#include "lens_default.h"
#include "param.h"
#include "proc.h"
#include "prototype.h"
#include "type.h"
#include "value.h"
#include "zero.h"

struct param_enum {
	struct value array;
	int percent;
	size_t *future_length;
	char *format;
	char const *ptr;
	char const *end;
	size_t width;
	struct protolib *abi_plib;
};

static struct param_enum *
param_printf_init(struct value *cb_args, size_t nargs,
		  struct value_dict *arguments)
{
	assert(nargs == 1);

	struct process *proc = cb_args[0].inferior;
	assert(proc != NULL);

	/* We expect a pointer to array.  */
	if (cb_args->type->type != ARGTYPE_POINTER
	    || cb_args->type->u.ptr_info.info->type != ARGTYPE_ARRAY)
		return NULL;

	/* The element type should be either character (for narrow
	 * strings) or an integral type (for wide strings).  */
	struct arg_type_info *et
		= cb_args->type->u.ptr_info.info->u.array_info.elt_type;
	if (et->type != ARGTYPE_INTEGRAL)
		return NULL;

	struct param_enum *self = malloc(sizeof(*self));
	if (self == NULL) {
	fail:
		free(self);
		return NULL;
	}
	self->width = type_sizeof(proc, et);
	if (self->width == (size_t) -1)
		goto fail;

	if (value_init_deref(&self->array, cb_args) < 0)
		goto fail;
	assert(self->array.type->type == ARGTYPE_ARRAY);

	self->format = (char *)value_get_data(&self->array, arguments);
	if (self->format == NULL) {
		value_destroy(&self->array);
		goto fail;
	}

	size_t size = value_size(&self->array, arguments);
	if (size == (size_t)-1) {
		value_destroy(&self->array);
		goto fail;
	}

	self->percent = 0;
	self->ptr = self->format;
	self->end = self->format + size;
	self->future_length = NULL;

	self->abi_plib = abi_get_protolib(proc->abi);
	assert(self->abi_plib != NULL);

	return self;
}

static void
drop_future_length(struct param_enum *self)
{
	if (self->future_length != NULL) {
		free(self->future_length);
		self->future_length = NULL;
	}
}

static int
simple(struct protolib *plib, const char *name,
       struct lens *lens, struct arg_type_info *retp)
{
	*retp = *protolib_lookup_basetype(plib, name, true);
	retp->lens = lens;
	retp->own_lens = 0;
	return 0;
}

static int
integer(struct protolib *plib, unsigned hlf, unsigned lng, bool sign,
	struct lens *lens, struct arg_type_info *retp)
{
	assert(lng <= 2);
	assert(hlf <= 2);
	static const char *ints[]
		= { "schar", "short", "int", "long", "llong" };
	static const char *uints[]
		= { "uchar", "ushort", "uint", "ulong", "ullong" };

	const char *name = (sign ? ints : uints)[2 + lng - hlf];
	return simple(plib, name, lens, retp);
}

static int
pointer(struct arg_type_info *elt_info, int own, struct lens *lens,
	struct arg_type_info *retp)
{
	type_init_pointer(retp, elt_info, own);

	retp->lens = lens;
	retp->own_lens = 0;

	return 0;
}

static int
array(struct param_enum *self, struct arg_type_info *elt_info,
      char *len_buf, size_t len_buf_len, struct lens *lens,
      struct arg_type_info *retp)
{
	struct arg_type_info *arr = malloc(sizeof(*arr));
	if (arr == NULL)
		return -1;

	struct expr_node *node = NULL;
	int own_node;
	if (len_buf_len != 0 || self->future_length != NULL) {
		struct tmp {
			struct expr_node node;
			struct arg_type_info type;
		};
		struct tmp *len = malloc(sizeof(*len));
		if (len == NULL) {
		fail:
			free(len);
			free(arr);
			return -1;
		}

		type_init_integral(&len->type, sizeof(long), false);

		long l;
		if (self->future_length != NULL) {
			l = *self->future_length;
			drop_future_length(self);
		} else {
			l = atol(len_buf);
		}

		expr_init_const_word(&len->node, l, &len->type, 0);

		node = build_zero_w_arg(&len->node, 1);
		if (node == NULL)
			goto fail;
		own_node = 1;

	} else {
		node = expr_node_zero();
		own_node = 0;
	}
	assert(node != NULL);

	type_init_array(arr, elt_info, 0, node, own_node);
	return pointer(arr, 1, lens, retp);
}

static int
param_printf_next(struct param_enum *self, struct arg_type_info *retp,
		  int *insert_stop)
{
	unsigned hlf = 0;
	unsigned lng = 0;
	char len_buf[25] = {};
	size_t len_buf_len = 0;
	struct lens *lens = NULL;

	struct arg_type_info *info = NULL;

	for (; self->ptr < self->end; self->ptr += self->width) {
		union {
			uint8_t u8;
			uint16_t u16;
			uint32_t u32;
			uint64_t u64;
			char buf[0];
		} u;
		memcpy(u.buf, self->ptr, self->width);
		switch (self->width) {
		case 1: u.u64 = u.u8; break;
		case 2: u.u64 = u.u16; break;
		case 4: u.u64 = u.u32; break;
		}
		uint64_t c = u.u64;

		if (!self->percent) {
			if (c == '%')
				self->percent = 1;
			continue;
		}

		switch (c) {
		case '#': case ' ': case '-':
		case '+': case 'I': case '\'':
			/* These are only important for formatting,
			 * not for interpreting the type.  */
			continue;

		case '*':
			/* Length parameter given in the next
			 * argument.  */
			if (self->future_length == NULL)
				/* This should really be an assert,
				 * but we can't just fail on invalid
				 * format string.  */
				self->future_length
					= malloc(sizeof(*self->future_length));

			if (self->future_length != NULL) {
				self->ptr += self->width;
				return integer(self->abi_plib, hlf, lng, true,
					       lens, retp);
			}

		case '0':
		case '1': case '2': case '3':
		case '4': case '5': case '6':
		case '7': case '8': case '9':
			/* Field length likewise, but we need to parse
			 * this to attach the appropriate string
			 * length expression.  */
			if (len_buf_len < sizeof(len_buf) - 1)
				len_buf[len_buf_len++] = c;
			continue;

		case 'h':
			if (hlf < 2)
				hlf++;
			continue;

		case 'l':
			if (lng < 2)
				lng++;
			continue;

		case 'q':
			lng = 2;
			continue;

		case 'L': /* long double */
			lng = 1;
			continue;

		case 'j': /* intmax_t */
			/*   XXX ABI should know */
			lng = 2;
			continue;

		case 't': /* ptrdiff_t */
		case 'Z': case 'z': /* size_t */
			lng = 1; /* XXX ABI should tell */
			continue;

		case 'd':
		case 'i':
			self->percent = 0;
			return integer(self->abi_plib, hlf, lng, true,
				       lens, retp);

		case 'o':
			lens = &octal_lens;
			goto uint;

		case 'x': case 'X':
			lens = &hex_lens;
			/* Fall through.  */
		case 'u':
		uint:
			self->percent = 0;
			return integer(self->abi_plib, hlf, lng, false,
				       lens, retp);

		case 'e': case 'E':
		case 'f': case 'F':
		case 'g': case 'G':
		case 'a': case 'A':
			self->percent = 0;
			return simple(self->abi_plib, "double", lens, retp);

		case 'c':
			if (lng != 0) {
				/* "lc" means wide character.  */
		case 'C':	/* "C" is like "lc".  */
				self->percent = 0;
				return simple(self->abi_plib, "wchar_t",
					      &string_lens, retp);
			} else {
				self->percent = 0;
				return simple(self->abi_plib, "char",
					      &string_lens, retp);
			}

		case 's':
			if (lng != 0) {
				/* "ls" means wide string.  */
		case 'S':	/* "S" is like "ls".  */
				info = protolib_lookup_basetype
					(self->abi_plib, "wchar_t", true);
			} else {
				info = protolib_lookup_basetype
					(self->abi_plib, "char", true);
			}

			self->percent = 0;
			return array(self, info, len_buf, len_buf_len,
				     &string_lens, retp);

		case 'p':
		case 'n': /* int* where to store no. of printed chars.  */
			self->percent = 0;
			return pointer(type_get_void(), 0, NULL, retp);

		case 'm': /* (glibc) print argument of errno */
		case '%':
			lng = 0;
			hlf = 0;
			self->percent = 0;
			continue;

		default:
			continue;
		}
	}

	*retp = *type_get_void();
	return 0;
}

static enum param_status
param_printf_stop(struct param_enum *self, struct value *value)
{
	if (self->future_length != NULL
	    && value_extract_word(value, (long *)self->future_length, NULL) < 0)
		drop_future_length(self);

	return PPCB_CONT;
}

static void
param_printf_done(struct param_enum *context)
{
	value_destroy(&context->array);
	free(context);
}

void
param_pack_init_printf(struct param *param, struct expr_node *arg, int own_arg)
{
	param_init_pack(param, PARAM_PACK_VARARGS, arg, 1, own_arg,
			&param_printf_init, &param_printf_next,
			&param_printf_stop, &param_printf_done);
}
