# This is the main config file of Unicorefuzz.
# It should be adapted for each fuzzing run.
import os
import struct

from unicorn import Uc
from unicorn.x86_const import UC_X86_REG_RAX, UC_X86_REG_RDX, UC_X86_REG_RDI, UC_X86_REG_RSI
from unicorefuzz.unicorefuzz import Unicorefuzz

# A place to put scratch memory to. Non-kernelspace address should be fine.
SCRATCH_ADDR = 0x0
# How much scratch to add. We don't ask for much. Default should be fine.
SCRATCH_SIZE = 0x1000

# The page size used by the emulator. Optional.
PAGE_SIZE = 0x1000

# Set a supported architecture
ARCH = "x86"

# The gdb port to connect to
GDB_HOST = "localhost"
GDB_PORT = 1234

# Either set this to load the module from the VM and break at module + offset...
# MODULE = "procfs1"
# BREAK_OFFSET = 0x10

# Or this to break at a fixed offset.
BREAK_ADDR = 0x30d4d0
# You cannot set MODULE and BREAKOFFSET at the same time

# Additional exits here.
# The Exit at entry + LENGTH will be added automatically.
EXITS = [0x3c80c0]
# Exits realtive to the initial rip (entrypoint + addr)
ENTRY_RELATIVE_EXITS = [39]

# The location used to store data and logs
WORKDIR = os.path.join(os.getcwd(), "unicore_workdir")

# Where AFL input should be read from
AFL_INPUTS = os.path.join(os.getcwd(), "afl_inputs")
# Where AFL output should be placed at
AFL_OUTPUTS = os.path.join(os.getcwd(), "afl_outputs")

# Optional AFL dictionary
AFL_DICT = None


def init_func(unicore_fuzz, uc):
    """
    An init function called before forking.
    This function may be used to set additional unicorn hooks and things.
    If you uc.run_emu here, you will trigger the forkserver. Try not to/do that in place_input. :)
    """
    pass



def place_input(ucf: Unicorefuzz, uc: Uc, input: bytes) -> None:
    pass