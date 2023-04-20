#include "kernel.h"
#include "lib.h"

// kernel.c
//
//    This is the kernel.


// INITIAL PHYSICAL MEMORY LAYOUT
//
//  +-------------- Base Memory --------------+
//  v                                         v
// +-----+--------------------+----------------+--------------------+---------/
// |     | Kernel      Kernel |       :    I/O | App 1        App 1 | App 2
// |     | Code + Data  Stack |  ...  : Memory | Code + Data  Stack | Code ...
// +-----+--------------------+----------------+--------------------+---------/
// 0  0x40000              0x80000 0xA0000 0x100000             0x140000
//                                             ^
//                                             | \___ PROC_SIZE ___/
//                                      PROC_START_ADDR

#define PROC_SIZE 0x40000       // initial state only

static proc processes[NPROC];   // array of process descriptors
                                // Note that `processes[0]` is never used.
proc* current;                  // pointer to currently executing proc

#define HZ 100                  // timer interrupt frequency (interrupts/sec)
static unsigned ticks;          // # timer interrupts so far

void schedule(void);
void run(proc* p) __attribute__((noreturn));

static uint8_t disp_global = 1;         // global flag to display memviewer

// PAGEINFO
//
//    The pageinfo[] array keeps track of information about each physical page.
//    There is one entry per physical page.
//    `pageinfo[pn]` holds the information for physical page number `pn`.
//    You can get a physical page number from a physical address `pa` using
//    `PAGENUMBER(pa)`. (This also works for page table entries.)
//    To change a physical page number `pn` into a physical address, use
//    `PAGEADDRESS(pn)`.
//
//    pageinfo[pn].refcount is the number of times physical page `pn` is
//      currently referenced. 0 means it's free.
//    pageinfo[pn].owner is a constant indicating who owns the page.
//      PO_KERNEL means the kernel, PO_RESERVED means reserved memory (such
//      as the console), and a number >=0 means that process ID.
//
//    pageinfo_init() sets up the initial pageinfo[] state.

typedef struct physical_pageinfo {
    int8_t owner;
    int8_t refcount;
} physical_pageinfo;

static physical_pageinfo pageinfo[PAGENUMBER(MEMSIZE_PHYSICAL)];

typedef enum pageowner {
    PO_FREE = 0,                // this page is free
    PO_RESERVED = -1,           // this page is reserved memory
    PO_KERNEL = -2              // this page is used by the kernel
} pageowner_t;

static void pageinfo_init(void);


// Memory functions

void check_virtual_memory(void);
void memshow_physical(void);
void memshow_virtual(x86_64_pagetable* pagetable, const char* name);
void memshow_virtual_animate(void);
x86_64_pagetable* generate_new_pagetable(pid_t pid);
uintptr_t find_free_page(pid_t pid);
uintptr_t find_unassigned_page();
pid_t find_free_process();
void free_process(pid_t pid);
int num_pages(pid_t pid);
int num_process_pages(pid_t pid);


// kernel(command)
//    Initialize the hardware and processes and start running. The `command`
//    string is an optional string passed from the boot loader.

static void process_setup(pid_t pid, int program_number);

void kernel(const char* command) {
    hardware_init();
    pageinfo_init();
    console_clear();
    virtual_memory_map(kernel_pagetable, 0, 0, PROC_START_ADDR, PTE_W | PTE_P);
    virtual_memory_map(kernel_pagetable, CONSOLE_ADDR, CONSOLE_ADDR, 4096, PTE_W | PTE_P | PTE_U);
    timer_init(HZ);


    // Set up process descriptors
    memset(processes, 0, sizeof(processes));
    for (pid_t i = 0; i < NPROC; i++) {
        processes[i].p_pid = i;
        processes[i].p_state = P_FREE;
    }

    if (command && strcmp(command, "fork") == 0) {
        process_setup(1, 4);
    } else if (command && strcmp(command, "forkexit") == 0) {
        process_setup(1, 5);
    } else if (command && strcmp(command, "test") == 0) {
        process_setup(1, 6);
    } else if (command && strcmp(command, "test2") == 0) {
        for (pid_t i = 1; i <= 2; ++i) {
            process_setup(i, 6);
        }
    } else {
        for (pid_t i = 1; i <= 4; ++i) {
            process_setup(i, i - 1);
        }
    }


    // Switch to the first process using run()
    run(&processes[1]);
}


// process_setup(pid, program_number)
//    Load application program `program_number` as process number `pid`.
//    This loads the application's code and data into memory, sets its
//    %rip and %rsp, gives it a stack page, and marks it as runnable.

void process_setup(pid_t pid, int program_number) {
    process_init(&processes[pid], 0);
    // processes[pid].p_pagetable = kernel_pagetabl

    processes[pid].p_pagetable = generate_new_pagetable(pid);
	if (processes[pid].p_pagetable == (x86_64_pagetable*) -1) {
		return;
	}
    
    // ++pageinfo[PAGENUMBER(kernel_pagetable)].refcount;
    // log_printf("refcount for page number %d is %d\n", PAGENUMBER(kernel_pagetable), pageinfo[PAGENUMBER(kernel_pagetable)].refcount);

    int r = program_load(&processes[pid], program_number, NULL);
    assert(r >= 0);

    processes[pid].p_registers.reg_rsp = MEMSIZE_VIRTUAL; //PROC_START_ADDR + PROC_SIZE * pid;
    uintptr_t stack_page = processes[pid].p_registers.reg_rsp - PAGESIZE;
	current->p_registers.reg_rdi = stack_page;

	uintptr_t p_stack_page = find_free_page(pid);
	if (p_stack_page == (uintptr_t) -1) {
		free_process(pid);
		processes[pid].p_registers.reg_rax = -1;
		return;
	}
    virtual_memory_map(processes[pid].p_pagetable, stack_page, p_stack_page,
                       PAGESIZE, PTE_P | PTE_W | PTE_U);
    processes[pid].p_state = P_RUNNABLE;
}

x86_64_pagetable* generate_new_pagetable(pid_t pid) {
    x86_64_pagetable* pagetable_array[5];
    for (int i = 0; i < 5; i++) {
        pagetable_array[i] = (x86_64_pagetable*) find_free_page(pid); 
        if (pagetable_array[i] == (x86_64_pagetable*) -1) {
            // log_printf("COULD NOT FIND ALL PAGES FOR PROCESS %d\n", pid);
			for (int j = 0; j < i + 1; j++) {
                // log_printf("Set page %d to free\n", PAGENUMBER(pagetable_array[i]));
				pageinfo[PAGENUMBER(pagetable_array[i])].owner = PO_FREE;
				pageinfo[PAGENUMBER(pagetable_array[i])].refcount = 0;
			}
            return (x86_64_pagetable*) -1;
        }
		// log_printf("allocated address: %d for process %d\n", PAGENUMBER(pagetable_array[i]), pid);
        memset((void*) pagetable_array[i], 0, PAGESIZE); 
    }
    pagetable_array[0]->entry[0] = 
        (x86_64_pageentry_t) pagetable_array[1] | PTE_W | PTE_U | PTE_P;
    pagetable_array[1]->entry[0] = 
        (x86_64_pageentry_t) pagetable_array[2] | PTE_W | PTE_U | PTE_P;
    pagetable_array[2]->entry[0] = 
        (x86_64_pageentry_t) pagetable_array[3] | PTE_W | PTE_U | PTE_P;
    pagetable_array[2]->entry[1] = 
        (x86_64_pageentry_t) pagetable_array[4] | PTE_W | PTE_U | PTE_P;
	
	// log_printf("successfully allocated page tables for pid: %d\n", pid);

    // map pages existing in kernel pagetable to process pagetable.
    vamapping vam;
    for (uintptr_t addr = 0; addr < PROC_START_ADDR; addr += PAGESIZE) {
        vam = virtual_memory_lookup(kernel_pagetable, addr);
        if (vam.pn >= 0) {
            virtual_memory_map(pagetable_array[0], addr, vam.pa, PAGESIZE, vam.perm);
        }
    }

	return pagetable_array[0];
}

// assign_physical_page(addr, owner)
//    Allocates the page with physical address `addr` to the given owner.
//    Fails if physical page `addr` was already allocated. Returns 0 on
//    success and -1 on failure. Used by the program loader.

int assign_physical_page(uintptr_t addr, int8_t owner) {
    if ((addr & 0xFFF) != 0
        || addr >= MEMSIZE_PHYSICAL
        || pageinfo[PAGENUMBER(addr)].refcount != 0) {
        return -1;
    } else {
		// log_printf("Set page %d to owner %d\n", PAGENUMBER(addr), owner);
        pageinfo[PAGENUMBER(addr)].refcount = 1;
        pageinfo[PAGENUMBER(addr)].owner = owner;
        return 0;
    }
}

void syscall_mapping(proc* p){

    uintptr_t mapping_ptr = p->p_registers.reg_rdi;
    uintptr_t ptr = p->p_registers.reg_rsi;

    //convert to physical address so kernel can write to it
    vamapping map = virtual_memory_lookup(p->p_pagetable, mapping_ptr);

    // check for write access
    if((map.perm & (PTE_W|PTE_U)) != (PTE_W|PTE_U))
        return;
    uintptr_t endaddr = mapping_ptr + sizeof(vamapping) - 1;
    // check for write access for end address
    vamapping end_map = virtual_memory_lookup(p->p_pagetable, endaddr);
    if((end_map.perm & (PTE_W|PTE_P)) != (PTE_W|PTE_P))
        return;
    // find the actual mapping now
    vamapping ptr_lookup = virtual_memory_lookup(p->p_pagetable, ptr);
    memcpy((void *)map.pa, &ptr_lookup, sizeof(vamapping));
}

void syscall_mem_tog(proc* process){

    pid_t p = process->p_registers.reg_rdi;
    if(p == 0) {
        disp_global = !disp_global;
    }
    else {
        if(p < 0 || p > NPROC || p != process->p_pid)
            return;
        process->display_status = !(process->display_status);
    }
}

// exception(reg)
//    Exception handler (for interrupts, traps, and faults).
//
//    The register values from exception time are stored in `reg`.
//    The processor responds to an exception by saving application state on
//    the kernel's stack, then jumping to kernel assembly code (in
//    k-exception.S). That code saves more registers on the kernel's stack,
//    then calls exception().
//
//    Note that hardware interrupts are disabled whenever the kernel is running.

void exception(x86_64_registers* reg) {
    // Copy the saved registers into the `current` process descriptor
    // and always use the kernel's page table.
    current->p_registers = *reg;
    set_pagetable(kernel_pagetable);

    // It can be useful to log events using `log_printf`.
    // Events logged this way are stored in the host's `log.txt` file.
    /*log_printf("proc %d: exception %d\n", current->p_pid, reg->reg_intno);*/

    // Show the current cursor location and memory state
    // (unless this is a kernel fault).
    console_show_cursor(cursorpos);
    if ((reg->reg_intno != INT_PAGEFAULT && reg->reg_intno != INT_GPF) // no error due to pagefault or general fault
            || (reg->reg_err & PFERR_USER)) // pagefault error in user mode 
    {
        check_virtual_memory();
        if(disp_global){
            memshow_physical();
            memshow_virtual_animate();
        }
    }

    // If Control-C was typed, exit the virtual machine.
    check_keyboard();


    // Actually handle the exception.
    switch (reg->reg_intno) {

    case INT_SYS_PANIC:
	    // rdi stores pointer for msg string
	    {
		char msg[160];
		uintptr_t addr = current->p_registers.reg_rdi;
		if((void *)addr == NULL)
		    panic(NULL);
		vamapping map = virtual_memory_lookup(current->p_pagetable, addr);
		memcpy(msg, (void *)map.pa, 160);
		panic(msg);

	    }
	    panic(NULL);
	    break;                  // will not be reached

    case INT_SYS_GETPID:
        current->p_registers.reg_rax = current->p_pid;
        break;

    case INT_SYS_YIELD:
        schedule();
        break;                  /* will not be reached */

    case INT_SYS_PAGE_ALLOC: {
        uintptr_t addr = current->p_registers.reg_rdi;
        if (addr < PROC_START_ADDR && (addr < CONSOLE_ADDR || addr > CONSOLE_ADDR + PAGESIZE)) {
            log_printf("allocated address is in kernel space\n");
            current->p_registers.reg_rax = -1;
            break;
        }
        else if (addr % PAGESIZE != 0) {
            log_printf("allocated address is not page-aligned\n");
            current->p_registers.reg_rax = -1;
            break;
        }
        else if (addr >= MEMSIZE_VIRTUAL) {
            log_printf("allocated address is out of range\n");
            current->p_registers.reg_rax = -1;
            break;
        }
        else {
            // obtain new physical page
			// log_printf("%d\n", current->p_pid);
            uintptr_t p_addr = find_free_page(current->p_pid);
            if (p_addr == (uintptr_t) -1) {
                log_printf("no valid physical page found to allocate: %d\n", current->p_registers.reg_rax);
				// free_process(current->p_pid);
                current->p_registers.reg_rax = -1;
                break;
            }
            virtual_memory_map(current->p_pagetable, addr, p_addr,
                               PAGESIZE, PTE_P | PTE_W | PTE_U);
            current->p_registers.reg_rax = 0;
            break;
        }
    }

    case INT_SYS_MAPPING:
    {
	    syscall_mapping(current);
            break;
    }

    case INT_SYS_MEM_TOG:
	{
	    syscall_mem_tog(current);
	    break;
	}

    case INT_TIMER:
        ++ticks;
        schedule();
        break;                  /* will not be reached */

    case INT_PAGEFAULT: {
        // Analyze faulting address and access type.
        uintptr_t addr = rcr2();
        const char* operation = reg->reg_err & PFERR_WRITE
                ? "write" : "read";
        const char* problem = reg->reg_err & PFERR_PRESENT
                ? "protection problem" : "missing page";

        if (!(reg->reg_err & PFERR_USER)) {
            panic("Kernel page fault for %p (%s %s, rip=%p)!\n",
                  addr, operation, problem, reg->reg_rip);
        }
        console_printf(CPOS(24, 0), 0x0C00,
                       "Process %d page fault for %p (%s %s, rip=%p)!\n",
                       current->p_pid, addr, operation, problem, reg->reg_rip);
        current->p_state = P_BROKEN;
        break;
    }

	case INT_SYS_FORK: 
		pid_t child_pid = find_free_process();
        if (child_pid < 0) {
            current->p_registers.reg_rax = -1;
            break;
        }
        // check if there are enough available pages to generate the new process
        if (num_pages(P_FREE) < num_pages(current->p_pid)) {
            current->p_registers.reg_rax = -1;
            break;
        }
        processes[child_pid].p_pagetable = generate_new_pagetable(child_pid);
        if (processes[child_pid].p_pagetable == (x86_64_pagetable*) -1) {
			processes[child_pid].p_state = P_FREE;
            current->p_registers.reg_rax = -1;
            break;
        }

        // make a copy for each page in parent's page table
        vamapping vam;
        for (uintptr_t page_addr = PROC_START_ADDR; page_addr < MEMSIZE_VIRTUAL; page_addr += PAGESIZE) {
            vam = virtual_memory_lookup(current->p_pagetable, page_addr);
            // if (pageinfo[vam.pn].owner == current->p_pid) {
            if ((vam.perm & (PTE_U | PTE_P)) == (PTE_U | PTE_P))  {
                if ((vam.perm & PTE_W) == PTE_W) {
                    uintptr_t page_cpy = find_free_page(child_pid);
                    if (page_cpy == (uintptr_t) -1) {
                        free_process(child_pid);
                        current->p_registers.reg_rax = -1;
                        break;
                    }
                    memcpy((void*) page_cpy, (void*) vam.pa, PAGESIZE);
                    virtual_memory_map(processes[child_pid].p_pagetable, page_addr, page_cpy, PAGESIZE, vam.perm);
                }
                else {
                    pageinfo[vam.pn].refcount++;
                    virtual_memory_map(processes[child_pid].p_pagetable, page_addr, vam.pa, PAGESIZE, vam.perm);
                }
            }
        }

		if ((int) current->p_registers.reg_rax == -1) {
			break;
		}

        // copy the registers, aside from rax
        // uint64_t prev_rax = processes[child_pid].p_registers.reg_rax;
        processes[child_pid].p_registers = processes[current->p_pid].p_registers;
        processes[child_pid].p_registers.reg_rax = 0;

        processes[child_pid].p_state = P_RUNNABLE;
        processes[child_pid].display_status = 1;
        current->p_registers.reg_rax = child_pid;
        break;

    case INT_SYS_EXIT:
		// log_printf("exited process %d\n", current->p_pid);
        free_process(current->p_pid);
        break;

    default:
        default_exception(current);
        break;                  /* will not be reached */

    }


    // Return to the current process (or run something else).
    if (current->p_state == P_RUNNABLE) {
        run(current);
    } else {
        schedule();
    }
}


// schedule
//    Pick the next process to run and then run it.
//    If there are no runnable processes, spins forever.

void schedule(void) {
    pid_t pid = current->p_pid;
    while (1) {
        pid = (pid + 1) % NPROC;
        if (processes[pid].p_state == P_RUNNABLE) {
            run(&processes[pid]);
        }
        // If Control-C was typed, exit the virtual machine.
        check_keyboard();
    }
}


// run(p)
//    Run process `p`. This means reloading all the registers from
//    `p->p_registers` using the `popal`, `popl`, and `iret` instructions.
//
//    As a side effect, sets `current = p`.

void run(proc* p) {
    assert(p->p_state == P_RUNNABLE);
    current = p;

    // Load the process's current pagetable.
    set_pagetable(p->p_pagetable);

    // This function is defined in k-exception.S. It restores the process's
    // registers then jumps back to user mode.
    exception_return(&p->p_registers);

 spinloop: goto spinloop;       // should never get here
}


// pageinfo_init
//    Initialize the `pageinfo[]` array.

void pageinfo_init(void) {
    extern char end[];

    for (uintptr_t addr = 0; addr < MEMSIZE_PHYSICAL; addr += PAGESIZE) {
        int owner;
        if (physical_memory_isreserved(addr)) {
            owner = PO_RESERVED;
        } else if ((addr >= KERNEL_START_ADDR && addr < (uintptr_t) end)
                   || addr == KERNEL_STACK_TOP - PAGESIZE) {
            owner = PO_KERNEL;
        } else {
            owner = PO_FREE;
        }
        pageinfo[PAGENUMBER(addr)].owner = owner;
        pageinfo[PAGENUMBER(addr)].refcount = (owner != PO_FREE);
    }
}


// check_page_table_mappings
//    Check operating system invariants about kernel mappings for page
//    table `pt`. Panic if any of the invariants are false.

void check_page_table_mappings(x86_64_pagetable* pt) {
    extern char start_data[], end[];
    assert(PTE_ADDR(pt) == (uintptr_t) pt);

    // kernel memory is identity mapped; data is writable
    for (uintptr_t va = KERNEL_START_ADDR; va < (uintptr_t) end;
         va += PAGESIZE) {
        vamapping vam = virtual_memory_lookup(pt, va);
        if (vam.pa != va) {
            console_printf(CPOS(22, 0), 0xC000, "%p vs %p\n", va, vam.pa);
        }
        assert(vam.pa == va);
        if (va >= (uintptr_t) start_data) {
            assert(vam.perm & PTE_W);
        }
    }

    // kernel stack is identity mapped and writable
    uintptr_t kstack = KERNEL_STACK_TOP - PAGESIZE;
    vamapping vam = virtual_memory_lookup(pt, kstack);
    assert(vam.pa == kstack);
    assert(vam.perm & PTE_W);
}


// check_page_table_ownership
//    Check operating system invariants about ownership and reference
//    counts for page table `pt`. Panic if any of the invariants are false.

static void check_page_table_ownership_level(x86_64_pagetable* pt, int level,
                                             int owner, int refcount);

void check_page_table_ownership(x86_64_pagetable* pt, pid_t pid) {
    // calculate expected reference count for page tables
    int owner = pid;
    int expected_refcount = 1;
    if (pt == kernel_pagetable) {
        owner = PO_KERNEL;
        for (int xpid = 0; xpid < NPROC; ++xpid) {
            if (processes[xpid].p_state != P_FREE
                && processes[xpid].p_pagetable == kernel_pagetable) {
                ++expected_refcount;
            }
        }
    }
    check_page_table_ownership_level(pt, 0, owner, expected_refcount);
}

static void check_page_table_ownership_level(x86_64_pagetable* pt, int level,
                                             int owner, int refcount) {
    assert(PAGENUMBER(pt) < NPAGES);
	// if (pageinfo[PAGENUMBER(pt)].owner != owner) {
		// log_printf("pagetable: %d, level: %d, owner: %d, refcount: %d, actual owner: %d\n", PAGENUMBER(pt), level, owner, refcount, pageinfo[PAGENUMBER(pt)].owner);
		// log_printf("owner status: %d\n", processes[owner].p_state);
	// }
    assert(pageinfo[PAGENUMBER(pt)].owner == owner);
    // log_printf("refcount for page %d is %d, expected to be %d\n", PAGENUMBER(pt), pageinfo[PAGENUMBER(pt)].refcount, refcount);
    assert(pageinfo[PAGENUMBER(pt)].refcount == refcount);
    if (level < 3) {
        for (int index = 0; index < NPAGETABLEENTRIES; ++index) {
            if (pt->entry[index]) {
                x86_64_pagetable* nextpt =
                    (x86_64_pagetable*) PTE_ADDR(pt->entry[index]);
                check_page_table_ownership_level(nextpt, level + 1, owner, 1);
            }
        }
    }
}


// check_virtual_memory
//    Check operating system invariants about virtual memory. Panic if any
//    of the invariants are false.

void check_virtual_memory(void) {
    // Process 0 must never be used.
    assert(processes[0].p_state == P_FREE);

    // The kernel page table should be owned by the kernel;
    // its reference count should equal 1, plus the number of processes
    // that don't have their own page tables.
    // Active processes have their own page tables. A process page table
    // should be owned by that process and have reference count 1.
    // All level-2-4 page tables must have reference count 1.

    check_page_table_mappings(kernel_pagetable);
    check_page_table_ownership(kernel_pagetable, -1);

    for (int pid = 0; pid < NPROC; ++pid) {
        if (processes[pid].p_state != P_FREE
            && processes[pid].p_pagetable != kernel_pagetable) {
            check_page_table_mappings(processes[pid].p_pagetable);
            check_page_table_ownership(processes[pid].p_pagetable, pid);
        }
    }

    // Check that all referenced pages refer to active processes
    for (int pn = 0; pn < PAGENUMBER(MEMSIZE_PHYSICAL); ++pn) {
        if (pageinfo[pn].refcount > 0 && pageinfo[pn].owner >= 0) {
            // if (processes[pageinfo[pn].owner].p_state == P_FREE) {
                // log_printf("Process %d free while page %d exists under its ownership\n", pageinfo[pn].owner, pn);
            // }
            assert(processes[pageinfo[pn].owner].p_state != P_FREE);
        }
    }
}

// memshow_physical
//    Draw a picture of physical memory on the CGA console.

static const uint16_t memstate_colors[] = {
    'K' | 0x0D00, 'R' | 0x0700, '.' | 0x0700, '1' | 0x0C00,
    '2' | 0x0A00, '3' | 0x0900, '4' | 0x0E00, '5' | 0x0F00,
    '6' | 0x0C00, '7' | 0x0A00, '8' | 0x0900, '9' | 0x0E00,
    'A' | 0x0F00, 'B' | 0x0C00, 'C' | 0x0A00, 'D' | 0x0900,
    'E' | 0x0E00, 'F' | 0x0F00, 'S'
};
#define SHARED_COLOR memstate_colors[18]
#define SHARED

void memshow_physical(void) {
    console_printf(CPOS(0, 32), 0x0F00, "PHYSICAL MEMORY");
    for (int pn = 0; pn < PAGENUMBER(MEMSIZE_PHYSICAL); ++pn) {
        if (pn % 64 == 0) {
            console_printf(CPOS(1 + pn / 64, 3), 0x0F00, "0x%06X ", pn << 12);
        }

        int owner = pageinfo[pn].owner;
        if (pageinfo[pn].refcount == 0) {
            owner = PO_FREE;
        }
        uint16_t color = memstate_colors[owner - PO_KERNEL];
        // darker color for shared pages
        if (pageinfo[pn].refcount > 1 && pn != PAGENUMBER(CONSOLE_ADDR)){
#ifdef SHARED
            color = SHARED_COLOR | 0x0F00;
#else
	    color &= 0x77FF;
#endif
        }

        console[CPOS(1 + pn / 64, 12 + pn % 64)] = color;
    }
}


// memshow_virtual(pagetable, name)
//    Draw a picture of the virtual memory map `pagetable` (named `name`) on
//    the CGA console.

void memshow_virtual(x86_64_pagetable* pagetable, const char* name) {
    assert((uintptr_t) pagetable == PTE_ADDR(pagetable));

    console_printf(CPOS(10, 26), 0x0F00, "VIRTUAL ADDRESS SPACE FOR %s", name);
    for (uintptr_t va = 0; va < MEMSIZE_VIRTUAL; va += PAGESIZE) {
        vamapping vam = virtual_memory_lookup(pagetable, va);
        uint16_t color;
        if (vam.pn < 0) {
            color = ' ';
        } else {
            assert(vam.pa < MEMSIZE_PHYSICAL);
            int owner = pageinfo[vam.pn].owner;
            if (pageinfo[vam.pn].refcount == 0) {
                owner = PO_FREE;
            }
            color = memstate_colors[owner - PO_KERNEL];
            // reverse video for user-accessible pages
            if (vam.perm & PTE_U) {
                color = ((color & 0x0F00) << 4) | ((color & 0xF000) >> 4)
                    | (color & 0x00FF);
            }
            // darker color for shared pages
            if (pageinfo[vam.pn].refcount > 1 && va != CONSOLE_ADDR) {
#ifdef SHARED
                color = (SHARED_COLOR | (color & 0xF000));
                if(! (vam.perm & PTE_U))
                    color = color | 0x0F00;

#else
		color &= 0x77FF;
#endif
            }
        }
        uint32_t pn = PAGENUMBER(va);
        if (pn % 64 == 0) {
            console_printf(CPOS(11 + pn / 64, 3), 0x0F00, "0x%06X ", va);
        }
        console[CPOS(11 + pn / 64, 12 + pn % 64)] = color;
    }
}


// memshow_virtual_animate
//    Draw a picture of process virtual memory maps on the CGA console.
//    Starts with process 1, then switches to a new process every 0.25 sec.

void memshow_virtual_animate(void) {
    static unsigned last_ticks = 0;
    static int showing = 1;

    // switch to a new process every 0.25 sec
    if (last_ticks == 0 || ticks - last_ticks >= HZ / 2) {
        last_ticks = ticks;
        ++showing;
    }

    // the current process may have died -- don't display it if so
    while (showing <= 2*NPROC
           && (processes[showing % NPROC].p_state == P_FREE || processes[showing % NPROC].display_status == 0)) {
        ++showing;
    }
    showing = showing % NPROC;

    if (processes[showing].p_state != P_FREE) {
        char s[4];
        snprintf(s, 4, "%d ", showing);
        memshow_virtual(processes[showing].p_pagetable, s);
    }
}

// find next available page to construct page table
uintptr_t find_unassigned_page() {
    for (uintptr_t page_addr = 0; page_addr < MEMSIZE_PHYSICAL; page_addr += PAGESIZE) {
        if (pageinfo[PAGENUMBER(page_addr)].owner == PO_FREE) {
            return page_addr;
        }
    }
    return (uintptr_t) -1;
}

// find next available page to construct page table
uintptr_t find_free_page(pid_t pid) {
    for (uintptr_t page_addr = 0; page_addr < MEMSIZE_PHYSICAL; page_addr += PAGESIZE) {
        if (pageinfo[PAGENUMBER(page_addr)].owner == PO_FREE && pageinfo[PAGENUMBER(page_addr)].refcount == 0) {
            // pageinfo[i].owner = pid;
            if (assign_physical_page(page_addr, pid) != 0) { 
                current->p_registers.reg_rax = -1;
                return (uintptr_t) -1;
            }
            return page_addr;
        }
    }
	current->p_registers.reg_rax = -1;
    return (uintptr_t) -1;
}

pid_t find_free_process() {
	for (int i = 1; i < NPROC; i++) {
		// procstate exam
		if (processes[i].p_state == P_FREE) {
			return i;
		}
	}
	current->p_registers.reg_rax = -1;
	return -1;
}

void free_process(pid_t pid) {
    // vamapping vam;
    // for (uintptr_t page_addr = 0; page_addr < MEMSIZE_VIRTUAL; page_addr += PAGESIZE) {
    //     vam = virtual_memory_lookup(processes[pid].p_pagetable, page_addr);
    //     if (vam.pn >= 0) {
    //         pageinfo[vam.pn].refcount--;
    //         if (pageinfo[vam.pn].refcount == 0) {
    //             pageinfo[vam.pn].owner = PO_FREE;
    //         }
    //     }
    // }

	for (int page_num = 0; page_num < PAGENUMBER(MEMSIZE_PHYSICAL); page_num++) {
		if (pageinfo[page_num].owner == pid) {
			pageinfo[page_num].refcount--;
			if (pageinfo[page_num].refcount == 0) {
				// log_printf("Setting page %d to free\n", page_num);
				pageinfo[page_num].owner = PO_FREE;
			}
		}
	}

	// log_printf("Freed process %d\n", pid);
    processes[pid].p_state = P_FREE;
    return;
}

int num_pages(pid_t pid) {
    int num_free = 0;
    for (int i = 0; i < PAGENUMBER(MEMSIZE_PHYSICAL); i++) {
        if (pageinfo[i].owner == pid)
            num_free++;
    }
    return num_free;
}

int num_process_pages(pid_t pid) {
    int num_used = 0;
    vamapping vam;
    for (uintptr_t page_addr = 0; page_addr < MEMSIZE_VIRTUAL; page_addr += PAGESIZE) {
        vam = virtual_memory_lookup(processes[pid].p_pagetable, page_addr);
        if (vam.pn >= 0)
            num_used++;
    }
    return num_used;
}
