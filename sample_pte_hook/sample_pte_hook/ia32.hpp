#pragma once

#include <cstdint>

#ifndef PAGE_SIZE
#define PAGE_SIZE 0x1000
#endif

// 64-bit PTE/PDE/PDPTE/PML4E simplified definitions
typedef union _pte_64 {
    uint64_t value;
    struct {
        uint64_t present : 1;
        uint64_t writable : 1;
        uint64_t user_accessible : 1;
        uint64_t write_through : 1;
        uint64_t cache_disable : 1;
        uint64_t accessed : 1;
        uint64_t dirty : 1;
        uint64_t pat : 1;
        uint64_t global : 1;
        uint64_t ignored1 : 3;
        uint64_t page_frame_number : 40;
        uint64_t reserved : 11;
        uint64_t nx : 1;
    };
} pte_64, *ppte_64;

typedef union _pde_64 {
    uint64_t value;
    struct {
        uint64_t present : 1;
        uint64_t writable : 1;
        uint64_t user_accessible : 1;
        uint64_t write_through : 1;
        uint64_t cache_disable : 1;
        uint64_t accessed : 1;
        uint64_t dirty : 1;
        uint64_t pat : 1;
        uint64_t large_page : 1;
        uint64_t ignored1 : 3;
        uint64_t page_frame_number : 40;
        uint64_t reserved : 11;
        uint64_t nx : 1;
    };
} pde_64, *ppde_64;

typedef union _pdpte_64 {
    uint64_t value;
    struct {
        uint64_t present : 1;
        uint64_t writable : 1;
        uint64_t user_accessible : 1;
        uint64_t write_through : 1;
        uint64_t cache_disable : 1;
        uint64_t accessed : 1;
        uint64_t reserved1 : 1;
        uint64_t reserved2 : 1;
        uint64_t ignored1 : 4;
        uint64_t page_frame_number : 40;
        uint64_t reserved : 11;
        uint64_t nx : 1;
    };
} pdpte_64, *ppdpte_64;

typedef union _pml4e_64 {
    uint64_t value;
    struct {
        uint64_t present : 1;
        uint64_t writable : 1;
        uint64_t user_accessible : 1;
        uint64_t write_through : 1;
        uint64_t cache_disable : 1;
        uint64_t accessed : 1;
        uint64_t reserved1 : 1;
        uint64_t reserved2 : 1;
        uint64_t ignored1 : 4;
        uint64_t page_frame_number : 40;
        uint64_t reserved : 11;
        uint64_t nx : 1;
    };
} pml4e_64, *ppml4e_64;

// CR3 (simplified): stores the PFN of the PML4 table in bits 12..51
typedef union _cr3 {
    uint64_t flags;
    struct {
        uint64_t reserved1 : 3;
        uint64_t write_protect : 1;
        uint64_t reserved2 : 7;
        uint64_t address_of_page_directory : 40;
        uint64_t reserved3 : 13;
    };
} cr3;

// Helper inline to read CR3 using compiler intrinsic; page_table_self_map.cpp calls __readcr3 directly
static inline cr3 make_cr3_from_uint64(uint64_t val) {
    cr3 r = { 0 };
    r.flags = val;
    return r;
}
