/*
 * This file is part of ltrace.
 * Copyright (C) 2011 Petr Machata, Red Hat Inc.
 * Copyright (C) 2006 Ian Wienand
 * Copyright (C) 2002,2008,2009 Juan Cespedes
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

#include "config.h"

#include <sys/ptrace.h>
#include <errno.h>
#include <string.h>
#include <stdio.h>
#include <stdbool.h>

#include "common.h"
#include "backend.h"
#include "sysdep.h"
#include "breakpoint.h"
#include "proc.h"
#include "library.h"
#include "type.h"
#include "value.h"

#ifdef ARCH_HAVE_ENABLE_BREAKPOINT
extern void arch_enable_breakpoint(pid_t, struct breakpoint *);
#else				/* ARCH_HAVE_ENABLE_BREAKPOINT */
void
arch_enable_breakpoint(pid_t pid, struct breakpoint *sbp)
{
	static unsigned char break_insn[] = BREAKPOINT_VALUE;
	unsigned int i, j;

	debug(DEBUG_PROCESS,
	      "arch_enable_breakpoint: pid=%d, addr=%p, symbol=%s",
	      pid, sbp->addr, breakpoint_name(sbp));

	for (i = 0; i < 1 + ((BREAKPOINT_LENGTH - 1) / sizeof(long)); i++) {
		long a = ptrace(PTRACE_PEEKTEXT, pid,
				sbp->addr + i * sizeof(long), 0);
		if (a == -1 && errno) {
			fprintf(stderr, "enable_breakpoint"
				" pid=%d, addr=%p, symbol=%s: %s\n",
				pid, sbp->addr, breakpoint_name(sbp),
				strerror(errno));
			return;
		}
		for (j = 0;
		     j < sizeof(long)
		     && i * sizeof(long) + j < BREAKPOINT_LENGTH; j++) {
			unsigned char *bytes = (unsigned char *)&a;

			sbp->orig_value[i * sizeof(long) + j] = bytes[j];
			bytes[j] = break_insn[i * sizeof(long) + j];
		}
		a = ptrace(PTRACE_POKETEXT, pid,
			   sbp->addr + i * sizeof(long), a);
		if (a == -1) {
			fprintf(stderr, "enable_breakpoint"
				" pid=%d, addr=%p, symbol=%s: %s\n",
				pid, sbp->addr, breakpoint_name(sbp),
				strerror(errno));
			return;
		}
	}
}
#endif				/* ARCH_HAVE_ENABLE_BREAKPOINT */

void
enable_breakpoint(Process *proc, struct breakpoint *sbp)
{
	debug(DEBUG_PROCESS, "enable_breakpoint: pid=%d, addr=%p, symbol=%s",
	      proc->pid, sbp->addr, breakpoint_name(sbp));
	arch_enable_breakpoint(proc->pid, sbp);
}

#ifdef ARCH_HAVE_DISABLE_BREAKPOINT
extern void arch_disable_breakpoint(pid_t, const struct breakpoint *sbp);
#else				/* ARCH_HAVE_DISABLE_BREAKPOINT */
void
arch_disable_breakpoint(pid_t pid, const struct breakpoint *sbp)
{
	unsigned int i, j;

	debug(DEBUG_PROCESS,
	      "arch_disable_breakpoint: pid=%d, addr=%p, symbol=%s",
	      pid, sbp->addr, breakpoint_name(sbp));

	for (i = 0; i < 1 + ((BREAKPOINT_LENGTH - 1) / sizeof(long)); i++) {
		long a = ptrace(PTRACE_PEEKTEXT, pid,
				sbp->addr + i * sizeof(long), 0);
		if (a == -1 && errno) {
			fprintf(stderr,
				"disable_breakpoint pid=%d, addr=%p: %s\n",
				pid, sbp->addr, strerror(errno));
			return;
		}
		for (j = 0;
		     j < sizeof(long)
		     && i * sizeof(long) + j < BREAKPOINT_LENGTH; j++) {
			unsigned char *bytes = (unsigned char *)&a;

			bytes[j] = sbp->orig_value[i * sizeof(long) + j];
		}
		a = ptrace(PTRACE_POKETEXT, pid,
			   sbp->addr + i * sizeof(long), a);
		if (a == -1 && errno) {
			fprintf(stderr,
				"disable_breakpoint pid=%d, addr=%p: %s\n",
				pid, sbp->addr, strerror(errno));
			return;
		}
	}
}
#endif				/* ARCH_HAVE_DISABLE_BREAKPOINT */

void
disable_breakpoint(Process *proc, struct breakpoint *sbp)
{
	debug(DEBUG_PROCESS, "disable_breakpoint: pid=%d, addr=%p, symbol=%s",
	      proc->pid, sbp->addr, breakpoint_name(sbp));
	arch_disable_breakpoint(proc->pid, sbp);
}

static Function *
void_prototype(void)
{
	static Function ret;
	if (ret.return_info == NULL)
		ret.return_info = type_get_voidptr();
	return &ret;
}

int
os_library_symbol_init(struct library_symbol *libsym)
{
	libsym->os = (struct os_library_symbol_data){};
	return 0;
}

void
os_library_symbol_destroy(struct library_symbol *libsym)
{
}

int
os_library_symbol_clone(struct library_symbol *retp,
			struct library_symbol *libsym)
{
	retp->os = libsym->os;
	return 0;
}

enum plt_status
os_elf_add_func_entry(struct Process *proc, struct ltelf *lte,
		      const GElf_Sym *sym,
		      arch_addr_t addr, const char *name,
		      struct library_symbol **ret)
{
	if (GELF_ST_TYPE(sym->st_info) == STT_FUNC)
		return plt_default;

	bool ifunc = false;
#ifdef STT_GNU_IFUNC
	ifunc = GELF_ST_TYPE(sym->st_info) == STT_GNU_IFUNC;
#endif

	if (ifunc) {
#define S ".IFUNC"
		char *tmp_name = malloc(strlen(name) + sizeof S);
		struct library_symbol *tmp = malloc(sizeof *tmp);
		if (tmp_name == NULL || tmp == NULL) {
		fail:
			free(tmp_name);
			free(tmp);
			return plt_fail;
		}
		sprintf(tmp_name, "%s%s", name, S);
#undef S

		if (library_symbol_init(tmp, addr, tmp_name, 1,
					LS_TOPLT_NONE) < 0)
			goto fail;
		tmp->proto = void_prototype();
		tmp->os.is_ifunc = 1;

		*ret = tmp;
		return plt_ok;
	}

	*ret = NULL;
	return plt_ok;
}

static enum callback_status
libsym_at_address(struct library_symbol *libsym, void *addrp)
{
	arch_addr_t addr = *(arch_addr_t *)addrp;
	return addr == libsym->enter_addr ? CBS_STOP : CBS_CONT;
}

static void
ifunc_ret_hit(struct breakpoint *bp, struct Process *proc)
{
	struct fetch_context *fetch = fetch_arg_init(LT_TOF_FUNCTION, proc,
						     type_get_voidptr());
	if (fetch == NULL)
		return;

	struct breakpoint *nbp = NULL;
	int own_libsym = 0;

	struct value value;
	value_init(&value, proc, NULL, type_get_voidptr(), 0);
	size_t sz = value_size(&value, NULL);
	union {
		uint64_t u64;
		uint32_t u32;
		arch_addr_t a;
	} u;

	if (fetch_retval(fetch, LT_TOF_FUNCTIONR, proc,
			 value.type, &value) < 0
	    || sz > 8 /* Captures failure as well.  */
	    || value_extract_buf(&value, (void *) &u, NULL) < 0) {
	fail:
		fprintf(stderr,
			"Couldn't trace the function "
			"indicated by IFUNC resolver.\n");
		goto done;
	}

	assert(sz == 4 || sz == 8);
	/* XXX double casts below:  */
	if (sz == 4)
		u.a = (arch_addr_t)(uintptr_t)u.u32;
	else
		u.a = (arch_addr_t)(uintptr_t)u.u64;

	assert(bp->os.ret_libsym != NULL);

	struct library *lib = bp->os.ret_libsym->lib;
	assert(lib != NULL);

	/* Look if we already have a symbol with this address.
	 * Otherwise create a new one.  */
	struct library_symbol *libsym
		= library_each_symbol(lib, NULL, libsym_at_address, &u.a);
	if (libsym == NULL) {
		libsym = malloc(sizeof *libsym);
		char *name = strdup(bp->os.ret_libsym->name);

		if (libsym == NULL
		    || name == NULL
		    || library_symbol_init(libsym, u.a, name, 1,
					   LS_TOPLT_NONE) < 0) {
			free(libsym);
			free(name);
			goto fail;
		}

		/* Snip the .IFUNC token.  */
		*strrchr(name, '.') = 0;

		own_libsym = 1;
		library_add_symbol(lib, libsym);
	}

	nbp = malloc(sizeof *bp);
	if (nbp == NULL || breakpoint_init(nbp, proc, u.a, libsym) < 0)
		goto fail;

	/* If there already is a breakpoint at that address, that is
	 * suspicious, but whatever.  */
	struct breakpoint *pre_bp = insert_breakpoint(proc, nbp);
	if (pre_bp == NULL)
		goto fail;
	if (pre_bp == nbp) {
		/* PROC took our breakpoint, so these resources are
		 * not ours anymore.  */
		nbp = NULL;
		own_libsym = 0;
	}

done:
	free(nbp);
	if (own_libsym) {
		library_symbol_destroy(libsym);
		free(libsym);
	}
	fetch_arg_done(fetch);
}

static int
create_ifunc_ret_bp(struct breakpoint **ret,
		    struct breakpoint *bp, struct Process *proc)
{
	*ret = create_default_return_bp(proc);
	if (*ret == NULL)
		return -1;
	static struct bp_callbacks cbs = {
		.on_hit = ifunc_ret_hit,
	};
	breakpoint_set_callbacks(*ret, &cbs);

	(*ret)->os.ret_libsym = bp->libsym;

	return 0;
}

int
os_breakpoint_init(struct Process *proc, struct breakpoint *bp)
{
	if (bp->libsym != NULL && bp->libsym->os.is_ifunc) {
		static struct bp_callbacks cbs = {
			.get_return_bp = create_ifunc_ret_bp,
		};
		breakpoint_set_callbacks(bp, &cbs);
	}
	return 0;
}

void
os_breakpoint_destroy(struct breakpoint *bp)
{
}

int
os_breakpoint_clone(struct breakpoint *retp, struct breakpoint *bp)
{
	return 0;
}
