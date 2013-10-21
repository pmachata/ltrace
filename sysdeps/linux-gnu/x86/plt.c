/*
 * This file is part of ltrace.
 * Copyright (C) 2013 Petr Machata, Red Hat Inc.
 * Copyright (C) 2004,2008,2009 Juan Cespedes
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

#include <gelf.h>
#include <stdbool.h>
#include <assert.h>

#include "proc.h"
#include "common.h"
#include "library.h"
#include "trace.h"
#include "backend.h"

GElf_Addr
arch_plt_sym_val(struct ltelf *lte, size_t ndx, GElf_Rela *rela)
{
	return lte->plt_addr + (ndx + 1) * 16;
}

void *
sym2addr(Process *proc, struct library_symbol *sym) {
	return sym->enter_addr;
}

enum plt_status
arch_elf_add_plt_entry(struct Process *proc, struct ltelf *lte,
		       const char *a_name, GElf_Rela *rela, size_t ndx,
		       struct library_symbol **ret)
{
	bool irelative = false;
	if (lte->ehdr.e_machine == EM_X86_64) {
#ifdef R_X86_64_IRELATIVE
		irelative = GELF_R_TYPE(rela->r_info) == R_X86_64_IRELATIVE;
#endif
	} else {
		assert(lte->ehdr.e_machine == EM_386);
#ifdef R_386_IRELATIVE
		irelative = GELF_R_TYPE(rela->r_info) == R_386_IRELATIVE;
#endif
	}

	if (irelative)
		return linux_elf_add_plt_entry_irelative(proc, lte, rela,
							 ndx, ret);

	return plt_default;
}
