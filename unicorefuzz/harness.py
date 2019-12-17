#!/usr/bin/env python
"""
Main (Unicorn-)Harness, used alongside AFL.
"""
import argparse
import os
import sys
import time
from typing import Optional, Tuple, Dict, List

from capstone import Cs
from unicorn import *
from unicorn.x86_const import *

from unicorefuzz import x64utils
from unicorefuzz.unicorefuzz import (
    Unicorefuzz,
    REJECTED_ENDING,
    X64,
    uc_get_pc,
    uc_reg_const,
)
from unicorefuzz.x64utils import syscall_exit_hook


def unicorn_debug_instruction(
    uc: Uc, address: int, size: int, user_data: "Unicorefuzz"
) -> None:
    cs = user_data.cs  # type: Cs
    try:
        mem = uc.mem_read(address, size)
        for (cs_address, cs_size, cs_mnemonic, cs_opstr) in cs.disasm_lite(
            bytes(mem), size
        ):
            print("    Instr: {:#016x}:\t{}\t{}".format(address, cs_mnemonic, cs_opstr))
    except Exception as e:
        print(hex(address))
        print("e: {}".format(e))
        print("size={}".format(size))
        for (cs_address, cs_size, cs_mnemonic, cs_opstr) in cs.disasm_lite(
            bytes(uc.mem_read(address, 30)), 30
        ):
            print("    Instr: {:#016x}:\t{}\t{}".format(address, cs_mnemonic, cs_opstr))


def unicorn_debug_block(uc: Uc, address: int, size: int, user_data: None) -> None:
    print("Basic Block: addr=0x{:016x}, size=0x{:016x}".format(address, size))


def unicorn_debug_mem_access(
    uc: Uc, access: int, address: int, size: int, value: int, user_data: None
) -> None:
    if access == UC_MEM_WRITE:
        print(
            "        >>> Write: addr=0x{:016x} size={} data=0x{:016x}".format(
                address, size, value
            )
        )
    else:
        print("        >>> Read: addr=0x{:016x} size={}".format(address, size))


def unicorn_debug_mem_invalid_access(
    uc: Uc, access: int, address: int, size: int, value: int, user_data: "Harness"
):
    harness = user_data  # type Unicorefuzz
    print(
        "unicorn_debug_mem_invalid_access(uc={}, access={}, addr=0x{:016x}, size={}, value={}, ud={})".format(
            uc, access, address, size, value, user_data
        )
    )
    if access == UC_MEM_WRITE_UNMAPPED:
        print(
            "        >>> INVALID Write: addr=0x{:016x} size={} data=0x{:016x}".format(
                address, size, value
            )
        )
    else:
        print("        >>> INVALID Read: addr=0x{:016x} size={}".format(address, size))
    try:
        harness.map_page(uc, address)
    except KeyboardInterrupt:
        uc.emu_stop()
        return False
    return True


class Harness(Unicorefuzz):
    """
    The default harness, receiving memory from probe wrapper and running it in unicorn.
    """

    def __init__(self, config) -> None:
        super().__init__(config)
        self.fetched_regs = None  # type: Optional[Dict[str, int]]

    def harness(self, input_file: str, wait: bool, debug: bool, trace: bool) -> None:
        """
        The default harness, receiving memory from probe wrapper and running it in unicorn.
        :param input_file: the file to read
        :param wait: if we want to wait
        :param debug: if we should enable unicorn debugger
        :param trace: trace or not
        """
        uc, entry, exits = self.uc_init(
            input_file, wait, trace, verbose=(debug or trace)
        )
        if debug:
            self.uc_debug(uc, entry_point=entry, exit_point=exits[0])
        else:
            self.uc_run(uc, entry, exits[0])

    def uc_init(
        self, input_file, wait: bool = False, trace: bool = False, verbose: bool = False
    ) -> Tuple[Uc, int, List[int]]:
        """
        Initializes unicorn with the given params
        :param input_file: input file to drop into the emulator with config.init_func
        :param wait: block until state dir becomes available
        :param trace: if we should add trace hooks to unicorn
        :param verbose: enables some more logging
        :return: Tuple of (unicorn, entry_point, exits)
        """
        config = self.config
        uc = Uc(self.arch.unicorn_arch, self.arch.unicorn_mode)

        if trace:
            print("[+] Settings trace hooks")
            uc.hook_add(UC_HOOK_BLOCK, unicorn_debug_block)
            uc.hook_add(UC_HOOK_CODE, unicorn_debug_instruction, self)
            uc.hook_add(
                UC_HOOK_MEM_WRITE | UC_HOOK_MEM_READ | UC_HOOK_MEM_FETCH,
                unicorn_debug_mem_access,
            )

        if wait:
            self.wait_for_probe_wrapper()

        if verbose:
            print("[*] Reading from file {}".format(input_file))

        # we leave out gs_base and fs_base on x64 since they start the forkserver
        self.uc_load_registers(uc)

        # let's see if the user wants a change.
        config.init_func(self, uc)

        # get pc from unicorn state since init_func may have altered it.
        pc = uc_get_pc(uc, self.arch)
        exits = self.calculate_exits(pc)
        # mappings used in init_func didn't have the pc yet.
        for ex in self._deferred_exits:
            self.set_exits(uc, ex, exits)
        self.map_known_mem(uc)
        if not exits:
            raise ValueError(
                "No exits founds. Would run forever... Please set an exit address in config.py."
            )
        entry_point = pc

        # On error: map memory, add exits.
        uc.hook_add(UC_HOOK_MEM_UNMAPPED, unicorn_debug_mem_invalid_access, self)

        if len(exits) > 1:
            # unicorn supports a single exit only (using the length param).
            # We'll path the binary on load if we have need to support more.
            if self.arch == X64:
                uc.hook_add(
                    UC_HOOK_INSN,
                    syscall_exit_hook,
                    user_data=(exits, os._exit),
                    arg1=UC_X86_INS_SYSCALL,
                )
            else:
                # TODO: (Fast) solution for X86, ARM, ...
                raise Exception(
                    "Multiple exits not yet supported for arch {}".format(self.arch)
                )

        # starts the afl forkserver
        self.uc_start_forkserver(uc)

        input_file = open(input_file, "rb")  # load afl's input
        input = input_file.read()
        input_file.close()

        try:
            config.place_input(self, uc, input)
        except Exception as ex:
            raise Exception(
                "[!] Error setting testcase for input {}: {}".format(input, ex)
            )
        return uc, entry_point, exits

    def uc_debug(self, uc: Uc, entry_point: int, exit_point: int) -> None:
        """
        Start uDdbg debugger for the given unicorn instance
        :param uc: The unicorn instance
        :param entry_point: Where to start
        :param exit_point: Exit point
        """
        print("[*] Loading debugger...")
        sys.path.append(self.uddbg_path)
        print(sys.path)
        # noinspection PyUnresolvedReferences
        from udbg import UnicornDbg

        udbg = UnicornDbg()

        # uddbg wants to know some mappings, read the current stat from unicorn to have $something...
        # TODO: Handle mappings differently? Update them at some point? + Proper exit after run?
        mappings = [
            (hex(start), start, (end - start + 1))
            for (start, end, perms) in uc.mem_regions()
        ]

        udbg.initialize(
            emu_instance=uc,
            entry_point=entry_point,
            exit_point=exit_point,
            hide_binary_loader=True,
            mappings=mappings,
        )

        def dbg_except(x, y):
            raise Exception(y)

        os.kill = dbg_except
        udbg.start()
        # TODO will never reach done, probably.
        print("[*] Done.")

    def uc_run(self, uc: Uc, entry_point: int, exit_point: int) -> None:
        """
        Run initialized unicorn
        :param entry_point: The entry point
        :param exit_point: First final address. Hack something to get more exits
        :param uc: The unicorn instance to run
        """
        try:
            uc.emu_start(begin=entry_point, until=exit_point, timeout=0, count=0)
        except UcError as e:
            print(
                "[!] Execution failed with error: {} at address {:x}".format(
                    e, uc_get_pc(uc, self.arch)
                )
            )
            self.force_crash(e)
        # Exit without clean python vm shutdown:
        # "The os._exit() function can be used if it is absolutely positively necessary to exit immediately"
        # Many times faster!
        os._exit(0)

    def map_known_mem(self, uc: Uc):
        """
        Maps all memory known
        :param uc:
        :return:
        """
        for filename in os.listdir(self.statedir):
            if (
                not filename.endswith(REJECTED_ENDING)
                and filename not in self.fetched_regs
            ):
                try:
                    address = int(filename, 16)
                    self.map_page(uc, address)
                except Exception:
                    pass

    def uc_start_forkserver(self, uc: Uc):
        """
        Starts the forkserver by executing an instruction on some scratch register
        :param uc: The unicorn to fork
        """
        scratch_addr = self.config.SCRATCH_ADDR
        scratch_size = self.config.SCRATCH_SIZE
        arch = self.arch

        sys.stdout.flush()  # otherwise children will inherit the unflushed buffer
        uc.mem_map(scratch_addr, scratch_size)

        if self.arch == X64:
            # prepare to do base register things
            regs = self.fetch_all_regs()
            gs_base = regs["gs_base"]
            fs_base = regs["fs_base"]

            # This will execute code -> starts afl-unicorn forkserver!
            x64utils.set_gs_base(uc, scratch_addr, gs_base)
            x64utils.set_fs_base(uc, scratch_addr, fs_base)
        else:
            # We still need to start the forkserver somehow to be consistent.
            # Let's emulate a nop for this.
            uc.mem_map(scratch_addr, scratch_size)
            uc.mem_write(scratch_addr, arch.insn_nop)
            uc.emu_start(scratch_addr, until=0, count=1)

    def _raise_if_reject(self, base_address: int, dump_file_name: str) -> None:
        """
        If dump_file_name + REJECTED_ENDING exists, raises exception
        :param base_address: the base addr we're currently working with
        :param dump_file_name: the dump filename
        """
        if os.path.isfile(dump_file_name + REJECTED_ENDING):
            with open(dump_file_name + REJECTED_ENDING, "r") as f:
                err = "".join(f.readlines()).strip()
                # TODO: Exception class?
                raise Exception(
                    "Page at 0x{:016x} was rejected by target: {}".format(
                        base_address, err
                    )
                )

    def fetch_page_blocking(self, address: int) -> Tuple[int, bytes]:
        """
        Fetches a page at addr in the harness, asking probe wrapper, if necessary.
        returns base_address, content
        """
        base_address = self.get_base(address)
        input_file_name = os.path.join(self.requestdir, "{0:016x}".format(address))
        dump_file_name = os.path.join(self.statedir, "{0:016x}".format(base_address))
        if base_address in self._mapped_page_cache.keys():
            return base_address, self._mapped_page_cache[base_address]
        else:
            self._raise_if_reject(base_address, dump_file_name)
            # Creating the input file == request
            if not os.path.isfile(dump_file_name):
                open(input_file_name, "a").close()
            print("Requesting page 0x{:016x} from `ucf attach`".format(base_address))
            while 1:
                self._raise_if_reject(base_address, dump_file_name)
                try:
                    with open(dump_file_name, "rb") as f:
                        content = f.read()
                        if len(content) < self.config.PAGE_SIZE:
                            time.sleep(0.001)
                            continue
                        self._mapped_page_cache[base_address] = content
                        return base_address, content
                except IOError:
                    pass

    def _fetch_register(self, name: str) -> int:
        """
        Loads the value of a register from the dumped state.
        Used internally: later, rely on `ucf.regs[regname]`.
        :param name The name
        :returns the content of the register
        """
        with open(os.path.join(self.statedir, name), "r") as f:
            return int(f.read())

    def uc_load_registers(self, uc: Uc) -> None:
        """
        Loads all registers to unicorn, called in the harness.
        """
        regs = self.fetch_all_regs()
        for key, value in regs.items():
            if key in self.arch.ignored_regs:
                # print("[d] Ignoring reg: {} (Ignored)".format(r))
                continue
            try:
                uc.reg_write(uc_reg_const(self.arch, key), value)
            except Exception as ex:
                print("[d] Faild to load reg: {} ({})".format(key, ex))
                pass

    def uc_reg_const(self, reg_name: str) -> int:
        """
        Gets the reg const for the current arch
        :param reg_name: the reg name
        :return: UC_ const for the register of this name
        """
        return uc_reg_const(self.arch, reg_name)

    def uc_reg_read(self, uc: Uc, reg_name: str) -> int:
        """
        Reads a register by name, resolving the UC const for the current architecture.
        Handles potential special cases like base registers
        :param uc: the unicorn instance to read the register from
        :param reg_name: the register name
        :return: register content
        """
        reg_name = reg_name.lower()
        if reg_name == "fs_base":
            return x64utils.get_fs_base(uc, self.config.SCRATCH_ADDR)
        if reg_name == "gs_base":
            return x64utils.get_gs_base(uc, self.config.SCRATCH_ADDR)
        else:
            return uc.reg_read(self.uc_reg_const(reg_name))

    def uc_read_page(self, uc: Uc, addr: int) -> Tuple[int, bytes]:
        """
        Reads a page at the given addr from unicorn.
        Resolves the base addr automatically.
        :param uc: The unicorn instance
        :param addr: An address inside the page to read
        :return: Tuple of (base_addr, content)
        """
        base_addr = self.get_base(addr)
        return base_addr, uc.mem_read(base_addr, self.config.PAGE_SIZE)

    def fetch_all_regs(self, refetch: bool = False) -> Dict[str, int]:
        """
        Fetches all registers from state folder
        :param refetch: reload them from disk (defaults to False)
        :return: regname to content mapping
        """
        if refetch or self.fetched_regs is None:
            self.fetched_regs = {}
            for reg_name in self.arch.reg_names:
                try:
                    self.fetched_regs[reg_name] = self._fetch_register(reg_name)
                except Exception as ex:
                    # print("Failed to retrieve register {}: {}".format(reg_name, ex))
                    pass
        return self.fetched_regs

    def uc_get_pc(self, uc) -> int:
        """
        Gets the current pc from unicorn for this arch
        :param uc: the unicorn instance
        :return: value of the pc
        """
        return uc_get_pc(uc, self.arch)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="Test harness for our sample kernel module"
    )
    parser.add_argument(
        "input_file",
        type=str,
        help="Path to the file containing the mutated input to load",
    )
    parser.add_argument(
        "-c", "--config", type=str, default="config.py", help="The config file to use."
    )
    parser.add_argument(
        "-d",
        "--debug",
        default=False,
        action="store_true",
        help="Starts the testcase in uUdbg (if installed)",
    )
    parser.add_argument(
        "-t",
        "--trace",
        default=False,
        action="store_true",
        help="Enables debug tracing",
    )
    parser.add_argument(
        "-w",
        "--wait",
        default=False,
        action="store_true",
        help="Wait for the state directory to be present",
    )
    args = parser.parse_args()

    Harness(args.config)
    Harness.harness(args.input_file, debug=args.debug, trace=args.trace, wait=args.wait)
