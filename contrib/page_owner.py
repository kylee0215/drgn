#!/usr/bin/env drgn
# Copyright (c) Canonical Ltd.
# SPDX-License-Identifier: LGPL-2.1-or-later

""" Script to dump page_owner information using drgn"""

from argparse import ArgumentParser
import re

from drgn import Object, cast, sizeof
from drgn.helpers.linux.kconfig import get_kconfig
from drgn.helpers.linux.mm import PFN_PHYS, PHYS_PFN, page_to_pfn, pfn_to_page
from drgn.helpers.linux.stackdepot import stack_depot_fetch


def DIV_ROUND_UP(n, d):
    return ((n) + (d) - 1) // (d)


try:
    MAX_ORDER_NR_PAGES = int(get_kconfig(prog)["CONFIG_ARCH_FORCE_MAX_ORDER"])
except:
    MAX_ORDER_NR_PAGES = 10

vmcoreinfo = prog["VMCOREINFO"].string_().decode()


def get_vmcoreinfo_number(item):
    match = re.search(r"^NUMBER\(%s\)=([0-9]+)$" % item, vmcoreinfo, flags=re.M)
    if match:
        return int(match.group(1))
    else:
        raise Exception("Cannot find %s in vmcoreinfo" % item)


SECTION_SIZE_BITS = get_vmcoreinfo_number("SECTION_SIZE_BITS")
MAX_PHYSMEM_BITS = get_vmcoreinfo_number("MAX_PHYSMEM_BITS")
SECTIONS_SHIFT = MAX_PHYSMEM_BITS - SECTION_SIZE_BITS

NR_MEM_SECTIONS = 1 << SECTIONS_SHIFT
PFN_SECTION_SHIFT = SECTION_SIZE_BITS - prog["PAGE_SHIFT"]

if get_kconfig(prog)["CONFIG_SPARSEMEM_EXTREME"]:
    SECTIONS_PER_ROOT = prog["PAGE_SIZE"].value_() // sizeof(
        prog.type("struct mem_section")
    )
else:
    SECTIONS_PER_ROOT = 1

NR_SECTION_ROOTS = DIV_ROUND_UP(NR_MEM_SECTIONS, SECTIONS_PER_ROOT)
SECTION_ROOT_MASK = SECTIONS_PER_ROOT - 1

SUBSECTION_SHIFT = 21
PFN_SUBSECTION_SHIFT = SUBSECTION_SHIFT - prog["PAGE_SHIFT"]
PAGES_PER_SUBSECTION = 1 << PFN_SUBSECTION_SHIFT

PAGES_PER_SECTION = 1 << PFN_SECTION_SHIFT
PAGE_SECTION_MASK = ~(PAGES_PER_SECTION - 1)

SECTION_HAS_MEM_MAP = 1 << prog["SECTION_HAS_MEM_MAP_BIT"].value_()
SECTION_IS_EARLY = 1 << prog["SECTION_IS_EARLY_BIT"].value_()

PAGE_EXT_OWNER = prog["PAGE_EXT_OWNER"].value_()
PAGE_EXT_OWNER_ALLOCATED = prog["PAGE_EXT_OWNER_ALLOCATED"].value_()

PAGE_EXT_INVALID = 1


def pfn_to_section_nr(pfn):
    return pfn >> PFN_SECTION_SHIFT


def section_nr_to_root(sec):
    return sec.value_() // SECTIONS_PER_ROOT


def nr_to_section(nr):
    root = section_nr_to_root(nr)
    if root >= NR_SECTION_ROOTS:
        raise Exception("root >= NR_SECTION_ROOTS")
    return prog["mem_section"][root][nr & SECTION_ROOT_MASK]


def valid_section(section):
    return bool(
        section.address_of_() and (section.section_mem_map & SECTION_HAS_MEM_MAP)
    )


def early_section(section):
    return bool(section.address_of_() and (section.section_mem_map & SECTION_IS_EARLY))


def subsection_map_index(pfn):
    return (pfn & ~(PAGE_SECTION_MASK)) // PAGES_PER_SUBSECTION


def pfn_section_valid(ms, pfn):
    idx = subsection_map_index(pfn)
    usage = ms.usage
    if usage:
        return (1 << idx) & usage.subsection_map
    else:
        return 0


def pfn_to_section(pfn):
    return nr_to_section(pfn_to_section_nr(pfn))


def pfn_valid(pfn):
    if PHYS_PFN(PFN_PHYS(pfn)) != pfn:
        return 0
    if pfn_to_section_nr(pfn) >= NR_MEM_SECTIONS:
        return 0
    ms = pfn_to_section(pfn)
    if not valid_section(ms):
        return 0
    ret = early_section(ms) or pfn_section_valid(ms, pfn)
    return ret


def page_ext_invalid(page_ext):
    if not page_ext:
        return True
    if page_ext.value_() & PAGE_EXT_INVALID == PAGE_EXT_INVALID:
        return True
    return False


def get_entry(base, index):
    return Object(
        prog,
        "struct page_ext *",
        (cast("unsigned long", base) + prog["page_ext_size"].value_() * index),
    )


def lookup_page_ext(page):
    pfn = page_to_pfn(page)
    section = pfn_to_section(pfn)
    page_ext = section.page_ext
    if page_ext_invalid(page_ext):
        return drgn.NULL(prog, "unsigned long")
    return get_entry(page_ext, pfn)


def page_ext_get(page):
    page_ext = lookup_page_ext(page)
    if page_ext:
        return page_ext


def get_page_owner(page_ext):
    addr = cast("unsigned long", page_ext) + prog["page_owner_ops"].offset
    return Object(prog, "struct page_owner *", addr)


min_low_pfn = prog["min_low_pfn"]
max_pfn = prog["max_pfn"]


def read_page_owner():
    if prog["page_owner_inited"].key.enabled.counter != 1:
        raise Exception("page_owner is not enabled")
    pfn = min_low_pfn
    while (not pfn_valid(pfn)) and (pfn & (MAX_ORDER_NR_PAGES - 1) != 0):
        pfn += 1
    while pfn < max_pfn:
        #
        # If the new page is in a new MAX_ORDER_NR_PAGES area,
        # validate the area as existing, skip it if not
        #
        if ((pfn & (MAX_ORDER_NR_PAGES - 1)) == 0) and (not pfn_valid(pfn)):
            pfn += MAX_ORDER_NR_PAGES - 1
            continue

        page = pfn_to_page(pfn)
        page_ext = page_ext_get(page)
        if not page_ext:
            pfn += 1
            continue

        if not (page_ext.flags & (1 << PAGE_EXT_OWNER)):
            pfn += 1
            continue

        if not (page_ext.flags & (1 << PAGE_EXT_OWNER_ALLOCATED)):
            pfn += 1
            continue

        page_owner = get_page_owner(page_ext)
        trace = stack_depot_fetch(page_owner.handle)
        print(
            "Page allocated via order %d, gfp_mask: 0x%x, pid: %d, tgid: %d (%s), ts %u ns, free_ts %u ns"
            % (
                page_owner.order,
                page_owner.gfp_mask,
                page_owner.pid,
                page_owner.tgid,
                page_owner.comm.string_().decode(),
                page_owner.ts_nsec,
                page_owner.free_ts_nsec,
            )
        )
        print("PFN: %d, Flags: 0x%x" % (pfn, page.flags))
        print(trace)
        pfn += 1 << page_owner.order


def read_page_owner_by_pfn(pfn):
    if prog["page_owner_inited"].key.enabled.counter != 1:
        raise Exception("page_owner is not enabled")
    if pfn < min_low_pfn or pfn > max_pfn or (not pfn_valid(pfn)):
        raise Exception("pfn is not valid")

    page = pfn_to_page(pfn)
    page_ext = page_ext_get(page)
    if not page_ext:
        raise Exception("page_ext is not present")

    if not (page_ext.flags & (1 << PAGE_EXT_OWNER)):
        print("page_owner flag is invalid")
        raise Exception("page_owner info is not present (never set?)")

    if page_ext.flags & (1 << PAGE_EXT_OWNER_ALLOCATED):
        print("page_owner tracks the page as allocated")
    else:
        print("page_owner tracks the page as freed")

    page_owner = get_page_owner(page_ext)
    print(
        "Page last allocated via order %d, gfp_mask: 0x%x, pid: %d, tgid: %d (%s), ts %u ns, free_ts %u ns"
        % (
            page_owner.order,
            page_owner.gfp_mask,
            page_owner.pid,
            page_owner.tgid,
            page_owner.comm.string_().decode(),
            page_owner.ts_nsec,
            page_owner.free_ts_nsec,
        )
    )
    print("PFN: %d, Flags: 0x%x" % (pfn, page.flags))

    if page_owner.handle:
        alloc_trace = stack_depot_fetch(page_owner.handle)
        print(alloc_trace)
    else:
        print("page_owner allocation stack trace missing")

    if page_owner.free_handle:
        free_trace = stack_depot_fetch(page_owner.free_handle)
        print("page last free stack trace:")
        print(free_trace)
    else:
        print("page_owner free stack trace missing")

    if page_owner.last_migrate_reason != -1:
        print(
            "page has been migrated, last migrate reason: %s"
            % prog["migrate_reason_names"][page_owner.last_migrate_reason]
            .string_()
            .decode()
        )


if __name__ == "__main__":
    parser = ArgumentParser(description="Dump page owner information")
    parser.add_argument(
        "--pfn",
        type=int,
        default=None,
        help="pfn number. Default is None if not provided.",
    )
    args = parser.parse_args()
    if args.pfn is None:
        read_page_owner()
    else:
        pfn = Object(prog, "unsigned long", args.pfn)
        read_page_owner_by_pfn(pfn)
