#include "fuzz.h"
#include <tsl/robin_map.h>

#include <ctime>

enum cmds {
	OP_READ,
	OP_WRITE,
	OP_IN,
	OP_OUT,
	OP_PCI_WRITE,
	OP_MSR_WRITE,
	OP_VMCALL,
	OP_HVCALL_POSTMESSAGE,
	OP_HVCALL_SIGNALEVENT,
	OP_CLOCK_STEP,
};

static bool log_ops = false;

std::map<bx_address, uint32_t> mmio_regions;
std::map<uint16_t, uint16_t> pio_regions;

static tsl::robin_map<bx_address, size_t> seen_dma;
uint16_t dma_start = 0;
uint16_t dma_len = 0;

/*
 * A pattern used to populate a DMA region or perform a memwrite. This is
 * useful for e.g. populating tables of unique addresses.
 * Example {.index = 1; .stride = 2; .len = 3; .data = "\x00\x01\x02"}
 * Renders as: 00 01 02   00 03 02   00 05 02   00 07 02 ...
 */
typedef struct {
	uint8_t index; /* Index of a byte to increment by stride */
	uint8_t stride; /* Increment each index'th byte by this amount */
	size_t len;
	const uint8_t *data;
} pattern;

/*
 * Allocate a block of memory and populate it with a pattern.
 */
static void *pattern_alloc(pattern p, size_t len) {
	int i;
	uint8_t *buf = (uint8_t *)malloc(len);
	uint8_t sum = 0;

	for (i = 0; i < len; ++i) {
		buf[i] = p.data[i % p.len];
		if ((i % p.len) == p.index) {
			buf[i] += sum;
			sum += p.stride;
		}
	}
	return buf;
}

void clear_seen_dma() {
	seen_dma.clear();
}

void fuzz_dma_read_cb(bx_phy_address addr, unsigned len, void *data) {
	uint8_t *buf;

	if (!fuzzing)
		return;

	if (seen_dma[addr + len - 1] == len)
		return;

	if (seen_dma.find(addr - 1) != seen_dma.end()) {
		seen_dma[addr + len - 1] = seen_dma[addr - 1] + len;
		seen_dma.erase(addr - 1);
	} else {
		seen_dma[addr + len - 1] = len;
	}
	size_t sectionlen = seen_dma[addr + len - 1];
	// might have multiple dma reads per op
	dma_len += len;

	if (sectionlen < 0x100) {
		// if DMA read is a reasonable size, obtain fuzz input for the
		// entire DMA read
		size_t l = len;
		buf = ic_ingest_buf(&l, SEPARATOR, SEPARATOR_LEN, -1, 0);
		if (buf == NULL) {
	        fuzz_emu_stop_unhealthy();
			return;
		}
		if (BX_CPU(id)->fuzztrace || log_ops) {
			printf("!dma inject: [HPA: %lx, GPA: %lx] len: %lx data: ",
			       addr, lookup_gpa_by_hpa(addr), len);
		}
		BX_MEM(0)->writePhysicalPage(BX_CPU(id), addr, l, (void *)buf);
		memcpy(data, buf, l);
	} else if (sectionlen > 0x1000) {
	} else {
		uint8_t buf[100];
		size_t source = addr + len + 1 - sectionlen;
		if ((source + len) >> 12 != (source >> 12))
			source -= len;
		BX_MEM(0)->readPhysicalPage(BX_CPU(id), source, len, buf);

		if (BX_CPU(id)->fuzztrace || log_ops) {
			printf("!dma inject: [HPA: %lx, GPA: %lx] len: %lx data: ",
			       addr, lookup_gpa_by_hpa(addr), len);
		}
		BX_MEM(0)->writePhysicalPage(BX_CPU(id), addr, len, buf);
	}
}

unsigned int num_mmio_regions() {
	return mmio_regions.size();
}

static bx_address mmio_region(int idx) {
	for (auto &it : mmio_regions) {
		if (idx == 0) {
			return it.first;
		}
		idx -= 1;
	}
	return 0;
}

static bx_address mmio_region_size(bx_address addr) {
	return mmio_regions[addr];
}

static unsigned int num_pio_regions() {
	return pio_regions.size();
}

static uint16_t pio_region(int idx) {
	for (auto &it : pio_regions) {
		if (idx == 0)
			return it.first;
		idx -= 1;
	}
	return 0;
}

static uint16_t pio_region_size(uint16_t addr) {
	return pio_regions[addr];
}

bool inject_halt() {
	BX_CPU(id)->VMwrite32(VMCS_32BIT_VMEXIT_REASON, VMX_VMEXIT_HLT);
	BX_CPU(id)->VMwrite32(VMCS_VMEXIT_QUALIFICATION, 0);
	return true;
}

// INJECTORS
bool inject_write(bx_address addr, int size, uint64_t val) {
	enum Sizes { Byte, Word, Long, Quad, end_sizes };
	BX_CPU(id)->VMwrite64(VMCS_64BIT_GUEST_PHYSICAL_ADDR, addr);

	uint32_t exit_reason =
		vmcs_translate_guest_physical_ept(addr, NULL, NULL);
	/* printf("Exit reason: %lx\n", exit_reason); */
	if (!exit_reason)
		return false;
	BX_CPU(id)->VMwrite32(VMCS_32BIT_VMEXIT_REASON, exit_reason);

	if (exit_reason == VMX_VMEXIT_EPT_VIOLATION)
		BX_CPU(id)->VMwrite32(VMCS_VMEXIT_QUALIFICATION, 2);
	else
		BX_CPU(id)->VMwrite32(VMCS_VMEXIT_QUALIFICATION, 0);

	BX_CPU(id)->set_reg64(BX_64BIT_REG_RDX, addr);
	BX_CPU(id)->set_reg64(BX_64BIT_REG_RAX, val);

	if (BX_CPU(id)->fuzztrace || log_ops) {
		printf("!write%d %lx %lx (reason: %lx)\n", size, addr, val,
		       exit_reason);
	}
	bx_address phy;
	int res = vmcs_linear2phy(BX_CPU(id)->VMread64(VMCS_GUEST_RIP), &phy);
	if (phy > maxaddr || !res) {
		printf("failed to write instruction to %lx (vaddr: %lx)\n",
		       BX_CPU(id)->VMread64(VMCS_GUEST_RIP), phy);
		return false;
	}
	switch (size) {
	case Byte:
		BX_CPU(id)->VMwrite32(VMCS_32BIT_VMEXIT_INSTRUCTION_LENGTH, 2);
		cpu_physical_memory_write(phy, "\x88\x02", 2);
		break;
	case Word:
		BX_CPU(id)->VMwrite32(VMCS_32BIT_VMEXIT_INSTRUCTION_LENGTH, 3);
		cpu_physical_memory_write(phy, "\x66\x89\x02", 3);
		break;
	case Long:
		BX_CPU(id)->VMwrite32(VMCS_32BIT_VMEXIT_INSTRUCTION_LENGTH, 2);
		cpu_physical_memory_write(phy, "\x89\x02", 2);
		break;
	case Quad:
		BX_CPU(id)->VMwrite32(VMCS_32BIT_VMEXIT_INSTRUCTION_LENGTH, 3);
		cpu_physical_memory_write(phy, "\x48\x89\x02", 3);
		break;
	}
	return true;
}

bool inject_read(bx_address addr, int size) {
	enum Sizes { Byte, Word, Long, Quad, end_sizes };

	uint32_t exit_reason =
		vmcs_translate_guest_physical_ept(addr, NULL, NULL);
	BX_CPU(id)->VMwrite32(VMCS_32BIT_VMEXIT_REASON, exit_reason);

	BX_CPU(id)->VMwrite32(VMCS_64BIT_GUEST_PHYSICAL_ADDR, addr);

	if (exit_reason == VMX_VMEXIT_EPT_VIOLATION)
		BX_CPU(id)->VMwrite32(VMCS_VMEXIT_QUALIFICATION, 1);
	else
		BX_CPU(id)->VMwrite32(VMCS_VMEXIT_QUALIFICATION, 0);

	BX_CPU(id)->set_reg64(BX_64BIT_REG_RCX, addr);

	if (BX_CPU(id)->fuzztrace || log_ops) {
		printf("!read%d %lx\n", size, addr);
	}
	bx_address phy;
	int res = vmcs_linear2phy(BX_CPU(id)->VMread64(VMCS_GUEST_RIP), &phy);
	if (phy > maxaddr || !res) {
		printf("failed to write instruction to %lx (vaddr: %lx)\n",
		       BX_CPU(id)->VMread64(VMCS_GUEST_RIP), phy);
		return false;
	}
	switch (size) {
	case Byte:
		cpu_physical_memory_write(phy,
					  "\x67\x8a\x01", // mov al,BYTE PTR
							  // [ecx]
					  3);
		BX_CPU(id)->VMwrite32(VMCS_32BIT_VMEXIT_INSTRUCTION_LENGTH, 3);
		break;
	case Word:
		cpu_physical_memory_write(phy,
					  "\x67\x66\x8b\x01", // mov ax,WORD PTR
							      // [ecx]
					  4);
		BX_CPU(id)->VMwrite32(VMCS_32BIT_VMEXIT_INSTRUCTION_LENGTH, 4);
		break;
	case Long:
		cpu_physical_memory_write(phy,
					  "\x67\x8b\x01", // mov eax,DWORD PTR
							  // [ecx]
					  3);
		BX_CPU(id)->VMwrite32(VMCS_32BIT_VMEXIT_INSTRUCTION_LENGTH, 3);
		break;
	case Quad:
		cpu_physical_memory_write(phy,
					  "\x48\x8b\x01", // mov rax,QWORD PTR
							  // [rcx]
					  3);
		BX_CPU(id)->VMwrite32(VMCS_32BIT_VMEXIT_INSTRUCTION_LENGTH, 3);
		break;
	}
	return true;
}

bool inject_in(uint16_t addr, uint16_t size) {
	enum Sizes { Byte, Word, Long, end_sizes };
	uint64_t field_64 = 0;
	if (BX_CPU(id)->fuzztrace || log_ops) {
		printf("!in%d %x\n", size, addr);
	}
	bx_address phy;
	int res = vmcs_linear2phy(BX_CPU(id)->VMread64(VMCS_GUEST_RIP), &phy);
	if (phy > maxaddr || !res) {
		printf("failed to write instruction to %lx (vaddr: %lx)\n",
		       BX_CPU(id)->VMread64(VMCS_GUEST_RIP), phy);
		return false;
	}
	switch (size) {
	case Byte:
		// writes the 'in' instruction with the appropriate size into
		// code
		cpu_physical_memory_write(phy, // L0 physical addr of $rip in
					       // L2, inside the saved VMCS
					  // uses VMREAD to read the VMCS's
					  // $rip, which is a GVA look for
					  // existing code somewhere that
					  // alreaedy does the conversion
					  "\xec", 1);
		BX_CPU(id)->VMwrite32(VMCS_32BIT_VMEXIT_INSTRUCTION_LENGTH, 1);
		break;
	case Word:
		cpu_physical_memory_write(phy, "\x66\xed", 2);
		BX_CPU(id)->VMwrite32(VMCS_32BIT_VMEXIT_INSTRUCTION_LENGTH, 2);
		field_64 |= 1; // access size
		break;
	case Long:
		cpu_physical_memory_write(phy, "\xed", 1);
		BX_CPU(id)->VMwrite32(VMCS_32BIT_VMEXIT_INSTRUCTION_LENGTH, 1);
		field_64 |= 3; // access size
		break;
	}
	BX_CPU(id)->VMwrite32(VMCS_32BIT_VMEXIT_REASON,
			      VMX_VMEXIT_IO_INSTRUCTION);

	field_64 |= (addr << 16); // port number
	field_64 |= (1 << 3); // //IN
	BX_CPU(id)->VMwrite32(VMCS_VMEXIT_QUALIFICATION, field_64);
	BX_CPU(id)->set_reg64(BX_64BIT_REG_RDX, addr);
	return true;
}

bool inject_out(uint16_t addr, uint16_t size, uint32_t value) {
	enum Sizes { Byte, Word, Long, end_sizes };
	uint64_t field_64 = 0;
	if (BX_CPU(id)->fuzztrace || log_ops) {
		printf("!out%d %x %x\n", size, addr, value);
	}
	bx_address phy;
	int res = vmcs_linear2phy(BX_CPU(id)->VMread64(VMCS_GUEST_RIP), &phy);
	if (phy > maxaddr || !res) {
		printf("failed to write instruction to %lx (vaddr: %lx)\n",
		       BX_CPU(id)->VMread64(VMCS_GUEST_RIP), phy);
		return false;
	}
	switch (size) {
	case Byte:
		cpu_physical_memory_write(phy, "\xee", 1);
		BX_CPU(id)->VMwrite32(VMCS_32BIT_VMEXIT_INSTRUCTION_LENGTH, 1);
		break;
	case Word:
		cpu_physical_memory_write(phy, "\x66\xef", 2);
		BX_CPU(id)->VMwrite32(VMCS_32BIT_VMEXIT_INSTRUCTION_LENGTH, 2);
		field_64 |= 1; // access size
		break;
	case Long:
		cpu_physical_memory_write(phy, "\xef", 1);
		BX_CPU(id)->VMwrite32(VMCS_32BIT_VMEXIT_INSTRUCTION_LENGTH, 1);
		field_64 |= 3; // access size
		break;
	}

	BX_CPU(id)->set_reg64(BX_64BIT_REG_RDX, addr);

	// write value for out
	BX_CPU(id)->set_reg64(BX_64BIT_REG_RAX, value);

	BX_CPU(id)->VMwrite32(VMCS_32BIT_VMEXIT_REASON,
			      VMX_VMEXIT_IO_INSTRUCTION);

	field_64 |= (addr << 16);
	BX_CPU(id)->VMwrite32(VMCS_VMEXIT_QUALIFICATION, field_64);
	return true;
}

uint32_t inject_pci_read(uint8_t device, uint8_t function, uint8_t offset) {
	uint32_t value;
	inject_out(0xcf8, 2,
		   (1U << 31) | (device << 11) | (function << 8) | offset);
	start_cpu();
	inject_in(0xcfc, 2);
	start_cpu();
	uint32_t val = BX_CPU(id)->gen_reg[BX_64BIT_REG_RAX].rrx;
	return val;
}

bool inject_pci_write(uint8_t device, uint8_t function, uint8_t offset,
		      uint32_t value) {
	inject_out(0xcf8, 2,
		   (1U << 31) | (device << 11) | (function << 8) | offset);
	start_cpu();
	inject_out(0xcfc, 2, value);
	start_cpu();
	return true;
}

bool inject_wrmsr(bx_address msr, uint64_t value) {
	bx_address phy;
	BX_CPU(id)->set_reg64(BX_64BIT_REG_RAX, value & 0xFFFFFFFF);
	BX_CPU(id)->set_reg64(BX_64BIT_REG_RDX, value >> 32);

	int res = vmcs_linear2phy(BX_CPU(id)->VMread64(VMCS_GUEST_RIP), &phy);
	if (phy > maxaddr || !res) {
		printf("failed to write instruction to %lx (vaddr: %lx)\n",
		       BX_CPU(id)->VMread64(VMCS_GUEST_RIP), phy);
		return false;
	}
	cpu_physical_memory_write(phy, "\x0f\x30", 2);
	BX_CPU(id)->VMwrite32(VMCS_32BIT_VMEXIT_INSTRUCTION_LENGTH, 2);
	BX_CPU(id)->VMwrite32(VMCS_32BIT_VMEXIT_REASON, VMX_VMEXIT_WRMSR);

	BX_CPU(id)->set_reg64(BX_64BIT_REG_RCX, msr);
	start_cpu();
	return true;
}

uint64_t inject_rdmsr(bx_address msr) {
	bx_address phy;
	int res = vmcs_linear2phy(BX_CPU(id)->VMread64(VMCS_GUEST_RIP), &phy);
	if (phy > maxaddr || !res) {
		printf("failed to write instruction to %lx (vaddr: %lx)\n",
		       BX_CPU(id)->VMread64(VMCS_GUEST_RIP), phy);
		return false;
	}
	cpu_physical_memory_write(phy, "\x0f\x32", 2);
	BX_CPU(id)->VMwrite32(VMCS_32BIT_VMEXIT_INSTRUCTION_LENGTH, 2);
	BX_CPU(id)->VMwrite32(VMCS_32BIT_VMEXIT_REASON, VMX_VMEXIT_RDMSR);

	BX_CPU(id)->set_reg64(BX_64BIT_REG_RCX, msr);
	start_cpu();
	return (BX_CPU(id)->get_reg64(BX_64BIT_REG_RDX) << 32) |
	       (BX_CPU(id)->get_reg64(BX_64BIT_REG_RAX) & 0xFFFFFFFF);
}

/* OPERATIONS */

bool op_write() {
	enum Sizes { Byte, Word, Long, Quad, end_sizes };
	uint8_t size;
	uint8_t base;
	uint32_t offset;
	uint64_t value;

	if (ic_ingest8(&size, 0, Quad))
		return false;
	if (!num_mmio_regions())
		return false;
	if (ic_ingest8(&base, 0, num_mmio_regions() - 1))
		return false;
	bx_address addr = mmio_region(base);

	if (ic_ingest32(&offset, 0, mmio_region_size(addr) - 1))
		return false;
	addr += offset;
	switch (size) {
	case Byte:
		uint8_t val8;
		if (ic_ingest8(&val8, 0, -1))
			return false;
		value = val8;
		break;
	case Word:
		uint16_t val16;
		if (ic_ingest16(&val16, 0, -1))
			return false;
		value = val16;
		break;
	case Long:
		uint32_t val32;
		if (ic_ingest32(&val32, 0, -1))
			return false;
		value = val32;
		break;
	case Quad:
		if (ic_ingest64(&value, 0, -1))
			return false;
		break;
	}

	if (!inject_write(addr, size, value))
		return false;

	start_cpu();

	return true;
}

bool op_read() {
	enum Sizes { Byte, Word, Long, Quad, end_sizes };
	uint8_t size;
	uint8_t base;
	// uint16_t offset;
	uint32_t offset;

	if (ic_ingest8(&size, 0, Quad))
		return false;
	if (!num_mmio_regions())
		return false;
	if (ic_ingest8(&base, 0, num_mmio_regions() - 1))
		return false;
	bx_address addr = mmio_region(base);
	if (ic_ingest32(&offset, 0, mmio_region_size(addr) - 1))
		return false;
	addr += offset;

	if (!inject_read(addr, size))
		return false;

	start_cpu();
	return true;
}

bool op_out() {
	enum Sizes { Byte, Word, Long, end_sizes };
	uint8_t size;
	uint8_t base;
	uint16_t offset;
	uint32_t value;

	if (ic_ingest8(&size, 0, Long))
		return false;
	if (!num_pio_regions())
		return false;
	if (ic_ingest8(&base, 0, num_pio_regions() - 1))
		return false;

	bx_address addr = pio_region(base);
	if (ic_ingest16(&offset, 0, pio_region_size(addr) - 1))
		return false;

	bx_address phy;
	addr += offset;
	uint64_t field_64 = 0;
	if (addr == 0x160)
		return false;
	switch (size) {
	case Byte:
		uint8_t val8;
		if (ic_ingest8(&val8, 0, -1))
			return false;
		value = val8;
		break;
	case Word:
		uint16_t val16;
		if (ic_ingest16(&val16, 0, -1))
			return false;
		value = val16;
		break;
	case Long:
		uint32_t val32;
		if (ic_ingest32(&val32, 0, -1))
			return false;
		value = val32;
		break;
	}

	if (!inject_out(addr, size, value))
		return false;
	start_cpu();
	return true;
}

bool op_in() {
	enum Sizes { Byte, Word, Long, end_sizes };
	uint8_t size;
	uint8_t base;
	uint16_t offset;

	if (ic_ingest8(&size, 0, Long))
		return false;
	if (!num_pio_regions())
		return false;
	if (ic_ingest8(&base, 0, num_pio_regions() - 1))
		return false;

	bx_address addr = pio_region(base);
	if (ic_ingest16(&offset, 0, pio_region_size(addr) - 1))
		return false;
	addr += offset;

	if (!inject_in(addr, size))
		return false;
	start_cpu();
	return true;
}

static uint8_t pci_dev;
static uint8_t pci_fn;
void set_pci_device(uint8_t dev, uint8_t function) {
	pci_dev = dev;
	pci_fn = function;
	uint32_t original = inject_pci_read(pci_dev, pci_fn, 4);
	inject_pci_write(pci_dev, pci_fn, 4, original |= 0b111);
}

bool op_pci_write() {
	uint8_t device = pci_dev;
	uint8_t function = pci_fn;
	uint8_t offset;
	uint32_t value;
	if (!pci_dev)
		return false;

	if (ic_ingest8(&offset, 0, 64))
		return false;
	offset *= 4;
	if (offset == 4)
		return false;
	if (offset <= 0x10 + 24 && offset + 4 >= 0x10) // dont let us shift
						       // around BARS
		return false;
	if (offset <= 0x30 + 0x4 && offset + 4 >= 0x30) // dont let us shift
							// around BARS
		return false;
	if (offset <= 0x34 + 0x4 && offset + 4 >= 0x34) // dont let us shift
							// around BARS
		return false;
	if (offset <= 0x38 + 4 && offset + 4 >= 0x38) // dont let us shift
						      // around BARS
		return false;

	bx_address phy;
	int res = vmcs_linear2phy(BX_CPU(id)->VMread64(VMCS_GUEST_RIP), &phy);
	if (phy > maxaddr || !res) {
		printf("failed to write instruction to %lx (vaddr: %lx)\n",
		       BX_CPU(id)->VMread64(VMCS_GUEST_RIP), phy);
		return false;
	}
	uint32_t val32;
	if (ic_ingest32(&val32, 0, -1))
		return false;
	value = val32;
	if (offset == 4) // dont let us shift around ROM
		value = (value & ~(0b11)) | 0b10;
	inject_pci_write(device, function, offset, value);
	return true;
}

bool op_msr_write() {
	uint32_t msr;
	uint64_t value;
	if (ic_ingest32(&msr, 0, -1))
		return false;
	if (ic_ingest64(&value, 0, -1))
		return false;

	if (BX_CPU(id)->fuzztrace || log_ops) {
		printf("!wrmsr %lx = %lx\n", msr, value);
	}
	return inject_wrmsr(msr, value);
}

static bx_gen_reg_t vmcall_gpregs[16 + 4];
static __typeof__(BX_CPU(id)->vmm) vmcall_xmmregs BX_CPP_AlignN(64);
static uint32_t vmcall_enabled_regs;

void insert_register_value_into_fuzz_input(int idx) {
	vmcall_enabled_regs |= (1 << idx);
}

/* Strategy:
 * vmcalls don't have a set ABI. Here are the examples of how they work for
 * various hypervisors:
 *
 * XEN:     RAX (call code), RDI, RSI, RDX, R10 R8
 * Hyper-V: RCX (rich call code), RDX, R8, XMM0-XMM5
 * KVM:     RAX (call code), RBX, RCX, RDX
 *
 * Setting all of that from the fuzzer input would waste a ton of fuzzer input.
 * Idea: Fill all guest registers with a random pattern. If this pattern pops up
 * later down the line, we know that for some reason the hypervisor cares about
 * it. With that information, we can modify the input to specify that the
 * corresponding register should be fuzzer provided.
 *
 * So a VMCALL looks like:
 * [opcode]
 * [bitfield to select which registers are fuzzer provided]
 * [the corresponding registers in natural order]
 */
bool op_vmcall() {
	static uint8_t local_dma[4096]; // Used to make a copy of dma data
					// before rewriting regs
	size_t local_dma_len; // Used to make a copy of dma data before
			      // rewriting regs
	const uint64_t fuzzable_regs_bitmap = (0b11111111111111001110);
	if (ic_ingest32(&vmcall_enabled_regs, 0, -1, true))
		return false;

	static bx_gen_reg_t gen_reg_snap[BX_GENERAL_REGISTERS + 4];

	static uint8_t xmm_reg_snap[sizeof(BX_CPU(id)->vmm)];

	// If the op was skipped, we need to reset the register state
	memcpy(vmcall_gpregs, BX_CPU(id)->gen_reg, sizeof(BX_CPU(id)->gen_reg));
	memcpy(vmcall_xmmregs, BX_CPU(id)->vmm, sizeof(BX_CPU(id)->vmm));
	vmcall_enabled_regs &= fuzzable_regs_bitmap;
	for (int i = 0; i < 16; i++) {
		if ((vmcall_enabled_regs >> i) & 1) {
			if (i == BX_64BIT_REG_RSP)
				continue;
			uint64_t val;
			if (ic_ingest64(&val, 0, -1)) {
				return false;
			}
			vmcall_gpregs[i].rrx = val;
		}
	}
	for (int i = 0; i < BX_XMM_REGISTERS; i++) {
		if ((vmcall_enabled_regs >> (16 + i)) & 1) {
			uint8_t *value =
				ic_ingest_len(sizeof(BX_CPU(id)->vmm[i]));
			if (!value) {
				return false;
			}
			memcpy(&vmcall_xmmregs[i], value,
			       sizeof(BX_CPU(id)->vmm[i]));
		}
	}

	BX_CPU(id)->VMwrite32(VMCS_32BIT_VMEXIT_REASON, VMX_VMEXIT_VMCALL);
	BX_CPU(id)->VMwrite32(VMCS_32BIT_VMEXIT_INSTRUCTION_LENGTH, 3);

	bx_address phy;
	int res = vmcs_linear2phy(BX_CPU(id)->VMread64(VMCS_GUEST_RIP), &phy);
	if (phy > maxaddr || !res) {
		printf("failed to write instruction to %lx (vaddr: %lx)\n",
		       BX_CPU(id)->VMread64(VMCS_GUEST_RIP), phy);
		return false;
	}
	cpu_physical_memory_write(phy, "\x0f\x01\xc1", 3);

	memcpy(BX_CPU(id)->gen_reg, vmcall_gpregs, sizeof(BX_CPU(id)->gen_reg));
	memcpy(BX_CPU(id)->vmm, vmcall_xmmregs, sizeof(BX_CPU(id)->vmm));

	uint8_t *dma_start = ic_get_cursor();

	if (BX_CPU(id)->fuzztrace || log_ops) {
		printf("!hypercall %lx\n", vmcall_gpregs[BX_64BIT_REG_RCX]);
	}
	start_cpu();
	/* printf("Hypercall %lx Result: %lx\n",vmcall_gpregs[BX_64BIT_REG_RCX],
	 * BX_CPU(id)->get_reg64(BX_64BIT_REG_RAX)); */

	uint8_t *dma_end = ic_get_cursor();

	local_dma_len = dma_end - dma_start;
	if (local_dma_len > sizeof(local_dma)) {
	    fuzz_emu_stop_unhealthy();
		return false;
	}
	memcpy(local_dma, dma_start, local_dma_len);

	ic_erase_backwards_until_token();
	vmcall_enabled_regs &= fuzzable_regs_bitmap;
	uint8_t opcode = OP_VMCALL;
	if (!ic_append(&opcode, sizeof(opcode)))
	    fuzz_emu_stop_unhealthy();
	if (!ic_append(&vmcall_enabled_regs, sizeof(vmcall_enabled_regs)))
	    fuzz_emu_stop_unhealthy();
	for (int i = 0; i < 16; i++) {
		if ((vmcall_enabled_regs >> i) & 1) {
			if (!ic_append(&vmcall_gpregs[i],
				       sizeof(vmcall_gpregs[i])))
	            fuzz_emu_stop_unhealthy();
		}
	}
	for (int i = 0; i < BX_XMM_REGISTERS; i++) {
		if ((vmcall_enabled_regs >> (16 + i)) & 1) {
			if (!ic_append(&vmcall_xmmregs[i],
				       sizeof(BX_CPU(id)->vmm[i])))
                fuzz_emu_stop_unhealthy();
		}
	}

	if (!ic_append(local_dma, local_dma_len))
        fuzz_emu_stop_unhealthy();
	return true;
}

bool op_hvcall_post_message() {
    uint32_t connection_id_val; // HV_CONNECTION_ID의 AsUInt32에 해당, 상위 8비트는 0으로 처리될 예정
    uint32_t message_type;
    uint32_t payload_size;
    uint8_t message_payload[240]; // TLFS 명시된 최대 페이로드 크기
    bx_phy_address param_gpa;     // L2 게스트 메모리에 파라미터 블록을 저장할 GPA

    // --- 1. 파라미터 블록으로 사용할 L2 GPA를 스크래치 리스트에서 무작위 선택 ---
    if (guest_page_scratchlist.empty()) {
        printf("Error: No scratch pages available for HvCallPostMessage params.\n");
        return false; 
    }
    uint8_t scratch_page_index = 0;
    if (guest_page_scratchlist.size() > 1) { 
        // 입력 스트림에서 인덱스 값을 읽어옴 (0 ~ 리스트크기-1 범위)
        // ic_ingest8은 output 버퍼에도 이 값을 추가함 (입력 재구성 시 활용)
        if (ic_ingest8(&scratch_page_index, 0, guest_page_scratchlist.size() - 1)) {
             // 입력 부족 시 기본값(0) 사용 또는 실패 처리. 여기서는 0으로 진행.
             scratch_page_index = 0; 
        }
    }
    param_gpa = guest_page_scratchlist[scratch_page_index];

    // 2. 퍼저 입력으로부터 하이퍼콜 파라미터 값들 읽기
    uint32_t id_24bit_part; // HV_CONNECTION_ID의 실제 ID 부분 (하위 24비트)
    // ic_ingest32로 0x00000000 ~ 0x00FFFFFF 범위의 값을 읽어옴
    // 이 값은 output 버퍼에도 추가됨
    if (ic_ingest32(&id_24bit_part, 0, 0x00FFFFFF)) return false; 
    connection_id_val = id_24bit_part; // connection_id_val은 이제 상위 8비트가 0인 UINT32 값이 됨

    // MessageType: MSB clear (0x0xxxxxxx), non-zero (1 ~ 0x7FFFFFFF 범위)
    if (ic_ingest32(&message_type, 1, 0x7FFFFFFF)) return false; 
    // PayloadSize: 0 ~ 240 범위
    if (ic_ingest32(&payload_size, 0, 240)) return false; 

    // 페이로드 데이터 읽기 (실제 payload_size 만큼)
    if (payload_size > 0) {
        uint8_t* ingested_payload_ptr = ic_ingest_len(payload_size);
        if (!ingested_payload_ptr) return false;
        memcpy(message_payload, ingested_payload_ptr, payload_size);
    }

    // 3. L2 게스트 메모리(param_gpa)에 파라미터 블록 구성
    bx_address param_hpa;
    int translation_level; 
    if (vmcs_translate_guest_physical_ept(param_gpa, &param_hpa, &translation_level) != 0) {
        printf("Error: Failed to translate GPA 0x%llx for HvCallPostMessage params.\n", (unsigned long long)param_gpa);
        return false; 
    }
    uint32_t rsvdz_at_offset4 = 0;
    // cpu_physical_memory_write 호출 시 connection_id_val 사용
    cpu_physical_memory_write(param_hpa + 0,  &connection_id_val, sizeof(connection_id_val)); // 수정됨: connection_id -> connection_id_val
    cpu_physical_memory_write(param_hpa + 4,  &rsvdz_at_offset4, sizeof(rsvdz_at_offset4));
    cpu_physical_memory_write(param_hpa + 8,  &message_type, sizeof(message_type));
    cpu_physical_memory_write(param_hpa + 12, &payload_size, sizeof(payload_size));
    if (payload_size > 0) {
        cpu_physical_memory_write(param_hpa + 16, message_payload, payload_size);
    }
    
    // 4. RCX (하이퍼콜 입력 값) 및 RDX (파라미터 GPA) 설정 준비
    uint64_t hypercall_input_value = 0x005C; // Call Code: 0x005C, Fast=0 등 기본값
    memcpy(vmcall_gpregs, BX_CPU(id)->gen_reg, sizeof(BX_CPU(id)->gen_reg)); 
    vmcall_gpregs[BX_64BIT_REG_RCX].rrx = hypercall_input_value;
    vmcall_gpregs[BX_64BIT_REG_RDX].rrx = param_gpa;             
    // vmcall_gpregs[BX_64BIT_REG_R8].rrx = 0; // 이 하이퍼콜은 R8을 명시적으로 사용 안 함

    // 5. VMCALL 주입 및 실행 준비 (이전과 동일)
    BX_CPU(id)->VMwrite32(VMCS_32BIT_VMEXIT_REASON, VMX_VMEXIT_VMCALL);
    BX_CPU(id)->VMwrite32(VMCS_32BIT_VMEXIT_INSTRUCTION_LENGTH, 3);
    bx_address phy_guest_rip;
    if (vmcs_linear2phy(BX_CPU(id)->VMread64(VMCS_GUEST_RIP), &phy_guest_rip) == 0) {
        printf("Error: Failed to translate GUEST_RIP for VMCALL injection.\n");
        return false;
    }
    cpu_physical_memory_write(phy_guest_rip, "\x0f\x01\xc1", 3); 

    // 6. 준비된 레지스터 값을 실제 Bochs CPU 레지스터로 복사 (이전과 동일)
    memcpy(BX_CPU(id)->gen_reg, vmcall_gpregs, sizeof(BX_CPU(id)->gen_reg));

    // --- 입력 재구성을 위한 DMA 데이터 캡처 준비 ---
    uint8_t *dma_data_output_start_cursor = ic_get_cursor();

    // 7. CPU 에뮬레이션 시작
    start_cpu(); 

    // 8. 하이퍼콜 반환 값(RAX) 확인 (선택적 로깅 - 이전과 동일, 필요시 상세화)
    uint64_t rax_return_value = BX_CPU(id)->get_reg64(BX_64BIT_REG_RAX);
    uint16_t hv_status = (uint16_t)(rax_return_value & 0xFFFF);
    if (BX_CPU(id)->fuzztrace || log_ops) { 
        printf("!HvCallPostMessage (0x005C) Attempted with GPA: 0x%llx, ConnID: 0x%08x, MsgType: 0x%08x, PayloadSize: %u\n",
               (unsigned long long)param_gpa, connection_id_val, message_type, payload_size);
        printf("  Returned: RAX=0x%016llx (Status=0x%04x)\n",
               (unsigned long long)rax_return_value, hv_status);
        // ... (필요시 HV_STATUS_INVALID_PARAMETER 세부 로깅) ...
    }

    // --- 9. 입력 재구성 로직 (op_vmcall과 유사하게) ---
    uint8_t *dma_data_output_end_cursor = ic_get_cursor();
    size_t dma_data_length_in_output = dma_data_output_end_cursor - dma_data_output_start_cursor;
    
    uint8_t temp_dma_buffer[4096]; 
    if (dma_data_length_in_output > sizeof(temp_dma_buffer)) {
        printf("Warning: DMA data (0x%zx bytes) too large for temp_dma_buffer in op_hvcall_post_message. Truncating.\n", dma_data_length_in_output);
        dma_data_length_in_output = sizeof(temp_dma_buffer); 
    }
    if (dma_data_length_in_output > 0) {
        memcpy(temp_dma_buffer, dma_data_output_start_cursor, dma_data_length_in_output);
    }

    ic_erase_backwards_until_token(); 

    uint8_t current_opcode = OP_HVCALL_POSTMESSAGE;
    if (!ic_append(&current_opcode, sizeof(current_opcode))) goto reconstruction_error_pm;

    // 사용된 파라미터 값들을 순서대로 output 버퍼에 다시 기록 (ic_ingest*가 이미 output에 추가했으므로,
    // 해당 값들이 output 버퍼의 현재 위치 이전에 올바르게 존재하고 있음.
    // ic_erase_backwards_until_token()은 마지막 SEPARATOR까지 지우므로,
    // 이 작업의 op_code와 파라미터들이 담긴 부분은 이미 지워진 상태.
    // 따라서, 사용된 값들을 다시 append 해주어야 함.)
    if (!ic_append(&scratch_page_index, sizeof(scratch_page_index))) goto reconstruction_error_pm;
    // connection_id_val은 id_24bit_part를 통해 ic_ingest32에서 이미 output에 기록됨.
    // 하지만 ic_erase_backwards_until_token()으로 지워졌으므로 여기서 다시 추가.
    // 이때, ic_ingest32가 output에 추가한 형식과 동일하게 추가해야 함 (UINT32로).
    if (!ic_append(&id_24bit_part, sizeof(id_24bit_part))) goto reconstruction_error_pm; // 또는 connection_id_val
    if (!ic_append(&message_type, sizeof(message_type))) goto reconstruction_error_pm;
    if (!ic_append(&payload_size, sizeof(payload_size))) goto reconstruction_error_pm;
    if (payload_size > 0) {
        if (!ic_append(message_payload, payload_size)) goto reconstruction_error_pm;
    }

    // 이 하이퍼콜 실행 중에 소비/주입된 DMA 데이터가 있다면, 그것도 output 버퍼에 추가
    if (dma_data_length_in_output > 0) {
        if (!ic_append(temp_dma_buffer, dma_data_length_in_output)) goto reconstruction_error_pm;
    }

    return true;

reconstruction_error_pm: // 레이블 이름 충돌 방지를 위해 _pm 추가
    fuzz_emu_stop_unhealthy(); 
    return false;
}

// HvCallSignalEvent (0x005D)를 위한 op 함수 (HV_CONNECTION_ID 제약 조건 반영)
bool op_hvcall_signal_event() {
    uint32_t connection_id_val; // HV_CONNECTION_ID의 AsUInt32에 해당, 상위 8비트는 0으로 처리
    uint16_t flag_number;
    bx_phy_address param_gpa; // 파라미터 블록을 저장할 L2 GPA

    // --- 1. 파라미터 블록으로 사용할 L2 GPA 확보 (스크래치 리스트에서 무작위 선택) ---
    if (guest_page_scratchlist.empty()) {
        printf("Error: No scratch pages available for HvCallSignalEvent params.\n");
        return false; 
    }
    uint8_t scratch_page_index = 0; // 기본값
    if (guest_page_scratchlist.size() > 1) { 
        // 입력 스트림에서 인덱스 값을 읽어옴 (0 ~ 리스트크기-1 범위)
        if (ic_ingest8(&scratch_page_index, 0, guest_page_scratchlist.size() - 1)) {
            scratch_page_index = 0; // 입력 부족 시 기본값 사용
        }
    }
    param_gpa = guest_page_scratchlist[scratch_page_index];
    // --- GPA 선택 로직 끝 ---

    // 2. 퍼저 입력으로부터 하이퍼콜 파라미터 값들 읽기
    uint32_t id_24bit_part; // HV_CONNECTION_ID의 실제 ID 부분 (하위 24비트)
    // ic_ingest32로 0x00000000 ~ 0x00FFFFFF 범위의 값을 읽어옴 (output 버퍼에도 추가됨)
    if (ic_ingest32(&id_24bit_part, 0, 0x00FFFFFF)) return false; 
    connection_id_val = id_24bit_part; // connection_id_val은 이제 상위 8비트가 0인 UINT32 값이 됨

    // FlagNumber: UINT16 범위. 
    // TLFS는 "port’s flag count" 미만이어야 한다고 하지만, 실제 값을 알 수 없으므로 전체 범위 퍼징.
    if (ic_ingest16(&flag_number, 0, 0xFFFF)) return false; 

    // 3. L2 게스트 메모리(param_gpa)에 파라미터 블록 구성
    bx_address param_hpa; // param_gpa에 해당하는 HPA
    int translation_level;
    if (vmcs_translate_guest_physical_ept(param_gpa, &param_hpa, &translation_level) != 0) {
        printf("Error: Failed to translate GPA 0x%llx for HvCallSignalEvent params.\n", (unsigned long long)param_gpa);
        return false; 
    }

    // 파라미터 블록을 HPA에 TLFS 명세에 따라 기록
    uint16_t rsvdz_at_offset6 = 0; // 예약된 필드는 0으로 설정

    // ConnectionId (상위 8비트가 0으로 처리된 값)를 파라미터 블록에 씀
    cpu_physical_memory_write(param_hpa + 0, &connection_id_val, sizeof(connection_id_val)); // Offset 0: ConnectionId (4 bytes)
    cpu_physical_memory_write(param_hpa + 4, &flag_number,       sizeof(flag_number));       // Offset 4: FlagNumber (2 bytes)
    cpu_physical_memory_write(param_hpa + 6, &rsvdz_at_offset6,  sizeof(rsvdz_at_offset6));  // Offset 6: RsvdZ (2 bytes)
    
    // 4. RCX (하이퍼콜 입력 값) 및 RDX (파라미터 GPA) 설정 준비
    uint64_t hypercall_input_value = 0x005D; // Call Code: 0x005D, Fast Flag = 0 등 기본값
    
    memcpy(vmcall_gpregs, BX_CPU(id)->gen_reg, sizeof(BX_CPU(id)->gen_reg)); // GPR 백업
    vmcall_gpregs[BX_64BIT_REG_RCX].rrx = hypercall_input_value; // RCX 설정
    vmcall_gpregs[BX_64BIT_REG_RDX].rrx = param_gpa;             // RDX 설정 (파라미터 블록 GPA)
    // vmcall_gpregs[BX_64BIT_REG_R8].rrx = 0; // R8은 메모리 기반 호출 시 명시적 사용 안함

    // 5. VMCALL 주입 및 실행 준비 (기존과 동일)
    BX_CPU(id)->VMwrite32(VMCS_32BIT_VMEXIT_REASON, VMX_VMEXIT_VMCALL);
    BX_CPU(id)->VMwrite32(VMCS_32BIT_VMEXIT_INSTRUCTION_LENGTH, 3); 

    bx_address phy_guest_rip;
    if (vmcs_linear2phy(BX_CPU(id)->VMread64(VMCS_GUEST_RIP), &phy_guest_rip) == 0) {
        printf("Error: Failed to translate GUEST_RIP for VMCALL injection.\n");
        return false;
    }
    cpu_physical_memory_write(phy_guest_rip, "\x0f\x01\xc1", 3); // GUEST_RIP에 VMCALL 명령어 삽입

    // 6. 준비된 레지스터 값을 실제 Bochs CPU 레지스터로 복사 (기존과 동일)
    memcpy(BX_CPU(id)->gen_reg, vmcall_gpregs, sizeof(BX_CPU(id)->gen_reg));

    // --- 입력 재구성을 위한 DMA 데이터 캡처 준비 ---
    uint8_t *dma_data_output_start_cursor = ic_get_cursor();
    // --- DMA 데이터 캡처 준비 끝 ---

    // 7. CPU 에뮬레이션 시작
    start_cpu(); 

    // 8. 하이퍼콜 반환 값(RAX) 확인 및 상세 로깅
    uint64_t rax_return_value = BX_CPU(id)->get_reg64(BX_64BIT_REG_RAX);
    uint16_t hv_status = (uint16_t)(rax_return_value & 0xFFFF);
    if (BX_CPU(id)->fuzztrace || log_ops) {
        printf("!HvCallSignalEvent (0x005D) Attempted with GPA: 0x%llx, ConnID: 0x%08x, FlagNum: 0x%04x\n",
               (unsigned long long)param_gpa, connection_id_val, flag_number);
        printf("  Returned: RAX=0x%016llx (Status=0x%04x)\n",
               (unsigned long long)rax_return_value, 
               hv_status); 
    }

    // --- 9. 입력 재구성 로직 ---
    uint8_t *dma_data_output_end_cursor = ic_get_cursor();
    size_t dma_data_length_in_output = dma_data_output_end_cursor - dma_data_output_start_cursor;
    
    uint8_t temp_dma_buffer[4096]; // 임시 DMA 버퍼
    if (dma_data_length_in_output > sizeof(temp_dma_buffer)) {
        printf("Warning: DMA data (0x%zx bytes) too large for temp_dma_buffer in op_hvcall_signal_event. Truncating.\n", dma_data_length_in_output);
        dma_data_length_in_output = sizeof(temp_dma_buffer);
    }
    if (dma_data_length_in_output > 0) {
        memcpy(temp_dma_buffer, dma_data_output_start_cursor, dma_data_length_in_output);
    }

    ic_erase_backwards_until_token(); // 이 작업으로 output에 추가된 내용 삭제

    // 정제된 작업 정보 output 버퍼에 다시 기록
    uint8_t current_opcode = OP_HVCALL_SIGNALEVENT; // 현재 작업 코드 명시
    if (!ic_append(&current_opcode, sizeof(current_opcode))) goto reconstruction_error_se;

    // 사용된 파라미터 값들을 순서대로 output 버퍼에 추가
    // ic_ingest* 함수들이 이미 output 버퍼에 올바른(제약된) 값을 기록했으므로,
    // 해당 값들을 참조하는 변수를 append하는 것이 아니라,
    // ic_ingest*가 기록한 그 '길이'만큼을 유지하도록 해야 함.
    // 여기서는 scratch_page_index, id_24bit_part(connection_id용), flag_number 순으로 append.
    if (!ic_append(&scratch_page_index, sizeof(scratch_page_index))) goto reconstruction_error_se;
    if (!ic_append(&id_24bit_part, sizeof(id_24bit_part))) goto reconstruction_error_se; // connection_id_val 대신 id_24bit_part
    if (!ic_append(&flag_number, sizeof(flag_number))) goto reconstruction_error_se;

    // 이 하이퍼콜 실행 중에 소비/주입된 DMA 데이터가 있다면, 그것도 output 버퍼에 추가
    if (dma_data_length_in_output > 0) {
        if (!ic_append(temp_dma_buffer, dma_data_length_in_output)) goto reconstruction_error_se;
    }

    return true;

reconstruction_error_se: // 레이블 이름 변경
    fuzz_emu_stop_unhealthy();
    return false;
    // --- 입력 재구성 로직 끝 ---
}

bool op_clock_step() {
	if (!getenv("END_WITH_CLOCK_STEP")) {
		printf("END_WITH_CLOCK_STEP is not set.\n");
		return false;
	} else if (in_clock_step < 0) {
		printf("END_WITH_CLOCK_STEP is not effective because SYMBOL_MAPPING is not well estabilished.\n");
		return false;
	}
	in_clock_step = CLOCK_STEP_GET_DEADLINE;

	uint64_t addr = mmio_regions.begin()->first;
	if (!inject_write(addr, 0 /*Byte*/, 0xff)) {
        in_clock_step = 0;
        return false;
	}
    start_cpu();
    in_clock_step = CLOCK_STEP_NONE;
    return true;
}

extern bool fuzz_unhealthy_input, fuzz_do_not_continue, fuzz_should_abort;
void fuzz_run_input(const uint8_t *Data, size_t Size) {
    bool (*ops[])() = {
        [OP_READ] = op_read,
        [OP_WRITE] = op_write,
        [OP_IN] = op_in,
        [OP_OUT] = op_out,
        [OP_PCI_WRITE] = op_pci_write,
        [OP_MSR_WRITE] = op_msr_write,
        [OP_VMCALL] = op_vmcall,
        [OP_HVCALL_POSTMESSAGE] = op_hvcall_post_message,
        [OP_HVCALL_SIGNALEVENT] = op_hvcall_signal_event,
    };
    // static const int nr_ops = sizeof(ops) / sizeof((ops)[0]); // 이 줄은 현재 코드에서 사용되지 않음

    static void *fuzz_legacy, *fuzz_hypercalls, *end_with_clockstep;
    static int inited;
    static bool is_hyperv_target = false;

    if (!inited) {
        // ... (inited 블록 내용은 동일) ...
        inited = 1;
        fuzz_legacy = getenv("FUZZ_LEGACY");
        fuzz_hypercalls = getenv("FUZZ_HYPERCALLS");
        end_with_clockstep = getenv("END_WITH_CLOCK_STEP");
        log_ops = getenv("LOG_OPS") || BX_CPU(id)->fuzztrace;
        
        const char* hyperv_env = getenv("HYPERV");
        if (hyperv_env && strcmp(hyperv_env, "1") == 0) {
            is_hyperv_target = true;
            printf("INFO: HYPERV target mode enabled for op selection.\n");
        } else {
            printf("INFO: HYPERV target mode disabled for op selection.\n");
        }
    }

    ic_new_input(Data, Size);
    uint16_t start = 0;
    uint8_t *input_start = ic_get_cursor();

    // num_defined_ops 선언을 루프 시작 전 또는 루프의 맨 위로 이동
    const size_t num_defined_ops = sizeof(ops) / sizeof(ops[0]);

    do {
        uint8_t op;
        dma_start = ic_get_cursor() - input_start; // dma_start, dma_len은 전역변수로 가정
        dma_len = 0;

        uint8_t min_op_for_ingest;
        uint8_t max_op_for_ingest;

        // ... (min_op_for_ingest, max_op_for_ingest 설정 로직은 동일) ...
        if (fuzz_legacy) {
            min_op_for_ingest = OP_READ;
            max_op_for_ingest = OP_OUT;
        } else if (fuzz_hypercalls) {
            min_op_for_ingest = OP_MSR_WRITE;
            if (is_hyperv_target) {
                max_op_for_ingest = OP_HVCALL_SIGNALEVENT; 
            } else {
                max_op_for_ingest = OP_VMCALL; 
            }
        } else { /* Fuzz Everything */
            min_op_for_ingest = 0; 
            if (is_hyperv_target) {
                max_op_for_ingest = OP_HVCALL_SIGNALEVENT; 
            } else {
                max_op_for_ingest = OP_VMCALL;
            }
        }


        if (ic_ingest8(&op, min_op_for_ingest, max_op_for_ingest, true)) {
            goto handle_op_failure_and_continue;
        }

        // ops 배열 범위 및 유효한 함수 포인터 확인 후 작업 실행
        if (op >= num_defined_ops || !ops[op] || !ops[op]()) { 
        handle_op_failure_and_continue: // 레이블 위치는 그대로 둠
            ic_erase_backwards_until_token();
            ic_subtract(4); 
            continue;
        }
        
        if (fuzz_unhealthy_input || fuzz_do_not_continue)
            break;
        if (new_op(op, start, (uint32_t)(ic_get_cursor() - input_start), dma_start,
               dma_len) >= 8) // 캐스팅 추가 (ic_get_cursor() - input_start의 타입이 ptrdiff_t일 수 있으므로)
            break;
    } while (ic_advance_until_token((const char*)SEPARATOR, sizeof(SEPARATOR))); // SEPARATOR 타입캐스팅 추가

    if (end_with_clockstep)
        op_clock_step();

    size_t dummy;
    uint8_t *output = ic_get_output(&dummy); 
}


void add_pio_region(uint16_t addr, uint16_t size) {
	pio_regions[addr] = size;
	printf("pio_regions %d = %lx + %lx\n", pio_regions.size(), addr, size);
}
void add_mmio_region(uint64_t addr, uint64_t size) {
	mmio_regions[addr] = size;
	printf("mmio_regions %d = %lx + %lx\n", mmio_regions.size(), addr,
	       size);
}
void add_mmio_range_alt(uint64_t addr, uint64_t end) {
	add_mmio_region(addr, end - addr);
}
void init_regions(const char *path) {
	open_db(path);
	if (getenv("FUZZ_ENUM")) {
		enum_pio_regions();
		enum_mmio_regions();
        exit(0);
	}
	if (getenv("MANUAL_RANGES")) {
		load_manual_ranges(getenv("MANUAL_RANGES"),
				   getenv("RANGE_REGEX"), pio_regions,
				   mmio_regions);
	} else {
		load_regions(pio_regions, mmio_regions);
	}
}
