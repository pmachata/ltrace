/*
 * This file is part of ltrace.
 * Copyright (C) 2011,2012,2013 Petr Machata, Red Hat Inc.
 * Copyright (C) 1997-2009 Juan Cespedes
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

#ifndef TYPE_H
#define TYPE_H

#include <stdbool.h>
#include <stddef.h>

#include "forward.h"
#include "vect.h"

enum arg_type {
	ARGTYPE_VOID,
	ARGTYPE_INTEGRAL,
	ARGTYPE_FLOATING,
	ARGTYPE_ARRAY,		/* Series of values in memory */
	ARGTYPE_STRUCT,		/* Structure of values */
	ARGTYPE_POINTER,	/* Pointer to some other type */
};

struct arg_type_info {
	enum arg_type type;
	union {
		struct vect entries;

		/* ARGTYPE_ARRAY */
		struct {
			struct arg_type_info *elt_type;
			struct expr_node *length;
			int own_info:1;
			int own_length:1;
		} array_info;

		/* ARGTYPE_POINTER */
		struct {
			struct arg_type_info *info;
			int own_info:1;
		} ptr_info;

		/* ARGTYPE_INTEGRAL, ARGTYPE_FLOATING */
		struct {
			unsigned bits;

			/* Always true for ARGTYPE_FLOATING.  */
			bool sign:1;
		} num_info;
	} u;

	struct lens *lens;
	int own_lens;
};

/* Returns a pointer to a simple type in a static buffer.  */
struct arg_type_info *type_get_void(void);
struct arg_type_info *type_get_voidptr(void);

/* Returns a long native to ltrace in a static buffer.  */
struct arg_type_info *type_get_native_long(void);

void type_init_integral(struct arg_type_info *info, unsigned bits, bool sign);
void type_init_floating(struct arg_type_info *info, unsigned bits);

/* Initialize INFO so it becomes ARGTYPE_STRUCT.  The created
 * structure contains no fields.  Use type_struct_add to populate the
 * structure.  */
void type_init_struct(struct arg_type_info *info);

/* Add a new field of type FIELD_INFO to a structure INFO.  If OWN,
 * the field type is owned and destroyed together with INFO.  */
int type_struct_add(struct arg_type_info *info,
		    struct arg_type_info *field_info, int own);

/* Get IDX-th field of structure type INFO.  */
struct arg_type_info *type_struct_get(struct arg_type_info *info, size_t idx);

/* Return number of fields of structure type INFO.  */
size_t type_struct_size(struct arg_type_info *info);

/* Return number of elements of an aggregate type INFO.  This can be
 * either ARGTYPE_STRUCT or ARGTYPE_ARRAY of constant length.  If
 * ARGTYPE_ARRAY does not have a constant length, this returns -1.  */
size_t type_aggregate_size(struct arg_type_info *info);

/* Initialize INFO so it becomes ARGTYPE_ARRAY.  The element type is
 * passed in ELEMENT_INFO, and array length in LENGTH_EXPR.  If,
 * respectively, OWN_INFO and OWN_LENGTH are true, the pointee and
 * length are owned and destroyed together with INFO.  */
void type_init_array(struct arg_type_info *info,
		     struct arg_type_info *element_info, int own_info,
		     struct expr_node *length_expr, int own_length);

/* Initialize INFO so it becomes ARGTYPE_POINTER.  The pointee type is
 * passed in POINTEE_INFO.  If OWN_INFO, the pointee type is owned and
 * destroyed together with INFO.  */
void type_init_pointer(struct arg_type_info *info,
		       struct arg_type_info *pointee_info, int own_info);

/* Release any memory associated with INFO.  Doesn't free INFO
 * itself.  */
void type_destroy(struct arg_type_info *info);

/* Copy type INFO into the area pointed to by RETP.  Return 0 on
 * success or a negative value on failure.  */
int type_clone(struct arg_type_info *retp, const struct arg_type_info *info);

/* Compute a size of given type.  Return (size_t)-1 for error.  */
size_t type_sizeof(struct process *proc, struct arg_type_info *type);

/* Compute an alignment necessary for elements of this type.  Return
 * (size_t)-1 for error.  */
size_t type_alignof(struct process *proc, struct arg_type_info *type);

/* Align value SZ to ALIGNMENT and return the result.  */
size_t align(size_t sz, size_t alignment);

/* Return ELT-th element of compound type TYPE.  This is useful for
 * arrays and structures.  */
struct arg_type_info *type_element(struct arg_type_info *type, size_t elt);

/* Compute an offset of EMT-th element of type TYPE.  This works for
 * arrays and structures.  Return (size_t)-1 for error.  */
size_t type_offsetof(struct process *proc,
		     struct arg_type_info *type, size_t elt);

/* If INFO is floating point equivalent type, return the corresponding
 * floating point type.  Otherwise return NULL.  Floating point
 * equivalent types are either ARGTYPE_FLOAT, or ARGTYPE_DOUBLE, or
 * ARGTYPE_STRUCT whose sole member is a floating point equivalent
 * type.  */
struct arg_type_info *type_get_fp_equivalent(struct arg_type_info *info);

/* If INFO is homogeneous floating-point aggregate, return the
 * corresponding floating point type, and set *COUNTP to number of
 * fields of the structure.  Otherwise return NULL.  INFO is a HFA if
 * it's an aggregate whose each field is either a HFA, or a
 * floating-point type.  */
struct arg_type_info *type_get_hfa_type(struct arg_type_info *info,
					size_t *countp);


#endif /* TYPE_H */
