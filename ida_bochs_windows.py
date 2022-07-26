# Helper script for Windows kernel debugging with IDA Pro on native Bochs debugger
# https://github.com/therealdreg/ida_bochs_windows
# GNU General Public License v3.0
#
# By Oleksiuk Dmytro (aka Cr4sh)
# Twitter @d_olex
# http://blog.cr4.sh
# cr4sh0@gmail.com
# https://github.com/Cr4sh
#
# Mod by David Reguera Garcia aka Dreg
# Twitter @therealdreg
# https://www.fr33project.org
# dreg@fr33project.org
# https://github.com/therealdreg
#
# 2022/07/14 by Dreg
#   - project renamed to ida_bochs_windows.py
#   - ported to python3
#   - ported to idapython 7.4: https://hex-rays.com/products/ida/support/ida74_idapython_no_bc695_porting_guide.shtml
#   - send_dbg_command('sreg') to get IDT address
#   - fixed bug in get_unistr with len
#   - code style fixed using black
#   - added changelog
#   - added some prints
#   - set all segments with +rwx
#   - lincense GNU General Public License v3.0
#   - comestic changes (new header...)
#   - added hal.dll to PDB_MODULES list
#   - ported to new pdb: netnode using $ pdb + altset 0 + supset 0
#   - tested:
#       - hosts: windows 10.0.19044 Build 19044
#       - ida pro 7.7, idapython 7.4
#       - targets: windows xp sp3 x86
#       - bochs debugger 2.7
#
# Features:
#
#   - Enumerating loaded kernel modules and segments creation for them.
#   - Loading debug symbols for kernel modules.
#
# Based on original vmware_modules.py from Hex Blog article: http://www.hexblog.com/?p=94
#
# Changes:
#   - Changed nt!PsLoadedModuleList finding algo, 'cause using FS segment base
#     for this -- is bad idea (FS not always points to the _KPCR).
#   - Added complete support of Windows x64.
#   - Fixed bugs in .PDB loading for mdules with the 'non-canonical' image path.

# Path to the folder, that contains files from the \SystemRoot\system32
# of your debug target.
SYSTEM32_COPY_PATH = r"C:\dreg\system32"

# Lave this list empty, if you want to load debug symbols for all modules.
# Otherwise -- specify list of the module file names.
PDB_MODULES = [
    "hal.dll",
    "ntoskrnl.exe",
    "ntkrnlpa.exe",
    "ntkrnlmp.exe",
    "ntkrpamp.exe",
    "win32k.sys",
]


def RQword(addr):
    return int.from_bytes(read_dbg_memory(addr, 8), "little")


def RDword(addr):
    return int.from_bytes(read_dbg_memory(addr, 4), "little")


def RWord(addr):
    return int.from_bytes(read_dbg_memory(addr, 2), "little")


def RByte(addr):
    return int.from_bytes(read_dbg_memory(addr, 1), "little")


def is_64bit():
    # Seems that idainfo.is_32bit() and idainfo.is_64bit() always
    # returns False (WTF?!) on my machines, so, I implemented a little hack
    # with the IDT location check on x86_64 canonical address.
    idtr_str = str(send_dbg_command('sreg').encode('ascii',errors='ignore'))
    idtr_str = idtr_str.split('idtr')[1].split('0x')[1].split(',')[0]
    idt = int(idtr_str, 16)
    print("idt addr: 0x%X" % idt)
    return (idt & 0xFFFFFF00) == 0xFFFFF800


if is_64bit():
    print("[+] 64-bit target")
    Ptr = RQword
    # type argument for SegCreate()
    segment_type = 2
    LIST_ENTRY_Blink = 8
    UNICODE_STRING_Buffer = 8
    LDR_DATA_TABLE_ENTRY_BaseAddress = 0x30
    LDR_DATA_TABLE_ENTRY_EntryPoint = 0x38
    LDR_DATA_TABLE_ENTRY_SizeOfImage = 0x40
    LDR_DATA_TABLE_ENTRY_FullDllName = 0x48
    LDR_DATA_TABLE_ENTRY_BaseDllName = 0x58
    IMAGE_NT_HEADERS_OptionalHeader = 0x18
    IMAGE_OPTIONAL_HEADER_SizeOfImage = 0x38

else:
    print("[+] 32-bit target")
    Ptr = RDword
    # type argument for SegCreate()
    segment_type = 1
    LIST_ENTRY_Blink = 4
    UNICODE_STRING_Buffer = 4
    LDR_DATA_TABLE_ENTRY_BaseAddress = 0x18
    LDR_DATA_TABLE_ENTRY_EntryPoint = 0x1C
    LDR_DATA_TABLE_ENTRY_SizeOfImage = 0x20
    LDR_DATA_TABLE_ENTRY_FullDllName = 0x24
    LDR_DATA_TABLE_ENTRY_BaseDllName = 0x2C
    IMAGE_NT_HEADERS_OptionalHeader = 0x18
    IMAGE_OPTIONAL_HEADER_SizeOfImage = 0x38


def find_sign(addr, sign):
    IMAGE_DOS_HEADER_e_lfanew = 0x3C
    # get image size from NT headers
    e_lfanew = RDword(addr + IMAGE_DOS_HEADER_e_lfanew)
    SizeOfImage = RDword(
        addr
        + e_lfanew
        + IMAGE_NT_HEADERS_OptionalHeader
        + IMAGE_OPTIONAL_HEADER_SizeOfImage
    )
    l = 0
    while l < SizeOfImage:
        matched = True
        for i in range(0, len(sign)):
            b = RByte(addr + l + i)
            if sign[i] is not None and sign[i] != b:
                matched = False
                break
        if matched:
            return addr + l
        l += 1
    raise Exception("find_sign(): Unable to locate signature")


def get_interrupt_vector_64(number):
    # get IDT base, GDB returns is as the following string:
    # idtr base=0xfffff80003400080 limit=0xfff
    idtr_str = str(send_dbg_command('sreg').encode('ascii',errors='ignore'))
    idtr_str = idtr_str.split('idtr')[1].split('0x')[1].split(',')[0]
    idt = int(idtr_str, 16)
    # go to the specified IDT descriptor
    idt += number * 16
    # build interrupt vector address
    descriptor_0 = RQword(idt)
    descriptor_1 = RQword(idt + 8)
    descriptor = (
        ((descriptor_0 >> 32) & 0xFFFF0000)
        + (descriptor_0 & 0xFFFF)
        + (descriptor_1 << 32)
    )
    return descriptor


def get_interrupt_vector_32(number):
    # get IDT base, GDB returns is as the following string:
    # idtr base=0x80b95400 limit=0x7ff
    idtr_str = str(send_dbg_command('sreg').encode('ascii',errors='ignore'))
    idtr_str = idtr_str.split('idtr')[1].split('0x')[1].split(',')[0]
    idt = int(idtr_str, 16)
    # go to the specified IDT descriptor
    idt += number * 8
    # build interrupt vector address
    descriptor_0 = RQword(idt)
    descriptor = ((descriptor_0 >> 32) & 0xFFFF0000) + (descriptor_0 & 0xFFFF)
    return descriptor


def find_PsLoadedModuleList_64(addr):
    # Find nt!PsLoadedModuleList on Windows x64 by
    # following signature from the nt!IoFillDumpHeader():
    #
    sign = [
        0xC7,
        0x43,
        0x30,
        0x64,
        0x86,
        0x00,
        0x00,  # mov     dword ptr [rbx+30h], 8664h
        0x89,
        0x93,
        0x98,
        0x0F,
        0x00,
        0x00,  # mov     [rbx+0F98h], edx
        0x48,
        0x8B,
        0x05,
        None,
        None,
        None,
        None,  # mov     rax, cs:MmPfnDatabase
        0x48,
        0x89,
        0x43,
        0x18,  # mov     [rbx+18h], rax
        0x48,
        0x8D,
        0x05,
        None,
        None,
        None,
        None,  # lea     rax, PsLoadedModuleList
    ]
    sign_offset = 24
    s = find_sign(addr, sign)
    return s + sign_offset + RDword(s + sign_offset + 3) + 7


def find_PsLoadedModuleList_32(addr):
    # Find nt!PsLoadedModuleList on Windows x32 by
    # following signature from the nt!IoFillDumpHeader():
    sign = [
        0xA1,
        None,
        None,
        None,
        None,  # mov     eax, ds:_MmPfnDatabase
        0x89,
        None,
        0x14,  # mov     [esi+14h], eax
        0xC7,
        None,
        0x18,
        None,
        None,
        None,
        None,  # mov     dword ptr [esi+18h], offset _PsLoadedModuleList
    ]
    sign_offset = 11
    s = find_sign(addr, sign)
    return RDword(s + sign_offset)


def get_unistr(addr):
    length = RWord(addr)
    start = Ptr(addr + UNICODE_STRING_Buffer)
    if length > 1000:
        raise Exception("get_unistr(): String too long")
    res = ""
    while length > 0:
        c = RWord(start)
        if c == 0:
            break
        res += chr(c)
        start += 2
        length -= 2
    return res


def walk_modulelist(list, callback):
    # get the first module
    cur_mod = Ptr(list)
    # loop until we come back to the beginning
    while cur_mod != list and cur_mod != BADADDR:
        BaseAddress = Ptr(cur_mod + LDR_DATA_TABLE_ENTRY_BaseAddress)
        EntryPoint = Ptr(cur_mod + LDR_DATA_TABLE_ENTRY_EntryPoint)
        SizeOfImage = Ptr(cur_mod + LDR_DATA_TABLE_ENTRY_SizeOfImage)
        FullDllName = get_unistr(cur_mod + LDR_DATA_TABLE_ENTRY_FullDllName).encode(
            "utf-8"
        )
        BaseDllName = get_unistr(cur_mod + LDR_DATA_TABLE_ENTRY_BaseDllName).encode(
            "utf-8"
        )
        # get next module (FLink)
        next_mod = Ptr(cur_mod)
        print(" * %s %s" % (str(hex(BaseAddress)), FullDllName))
        if callback is not None:
            callback(BaseAddress, BaseDllName, FullDllName, SizeOfImage, EntryPoint)
        # check that BLink points to the previous structure
        if Ptr(next_mod + LIST_ENTRY_Blink) != cur_mod:
            raise Exception("walk_modulelist(): List error")
        cur_mod = next_mod


def get_module_base(addr):
    if is_64bit():
        page_mask = 0xFFFFFFFFFFFFF000
    else:
        page_mask = 0xFFFFF000
    # align address by PAGE_SIZE
    addr &= page_mask
    # find module base by address inside it
    l = 0
    while l < 5 * 1024 * 1024:
        # check for the MZ signature
        w = RWord(addr - l)
        if w == 0x5A4D:
            return addr - l
        l += 0x1000
    raise Exception("get_module_base(): Unable to locate DOS signature")


def add_segment_callback(
    BaseAddress, BaseDllName, FullDllName, SizeOfImage, EntryPoint
):
    print(
        "BaseAddress: 0x%X , BaseDllName %s , FullDllName %s"
        % (BaseAddress, BaseDllName, FullDllName)
    )
    # do we already have a segment for this module?
    if (
        get_segm_start(BaseAddress) != BaseAddress
        or get_segm_end(BaseAddress) != BaseAddress + SizeOfImage
    ):
        try:
            # if not, create one
            AddSeg(
                BaseAddress,
                BaseAddress + SizeOfImage,
                0,
                segment_type,
                saRelByte,
                scPriv,
            )
            set_segm_attr(BaseAddress, SEGATTR_PERM, 7)
            set_segm_name(BaseAddress, BaseDllName.decode("UTF-8"))
        except:
            pass


def load_pdb_callback(BaseAddress, BaseDllName, FullDllName, SizeOfImage, EntryPoint):
    BaseDllName = BaseDllName.decode("UTF-8")
    FullDllName = FullDllName.decode("UTF-8")
    if len(PDB_MODULES) > 0 and BaseDllName.lower() not in PDB_MODULES:
        return  # skip this module
    # fix the path, that starts with the windows folder name
    if FullDllName.lower().startswith("\\windows\\system32"):
        FullDllName = "\\SystemRoot\\system32" + FullDllName[17:]
    # fix the path, that contains file name only
    if FullDllName.find("\\") == -1:
        FullDllName = "\\SystemRoot\\system32\\DRIVERS\\" + FullDllName
    # load modules from the System32 only
    if FullDllName.lower().startswith("\\systemroot\\system32"):
        # translate into local filename
        filename = SYSTEM32_COPY_PATH + FullDllName[20:]
        if is_64bit():
            val = 0xFFFFFFFFFFFFFFFE
        else:
            val = 0xFFFFFFFE
        penode = idaapi.netnode()
        penode.create("$ pdb")
        # set parameters for PDB plugin
        penode.altset(0, BaseAddress)
        penode.supset(0, filename)
        # load symbols
        print("Trying to load symbols for %s from %s" % (BaseDllName, filename))
        load_and_run_plugin("pdb", 3)  # use 1 to get a confirmation prompt
    else:
        print("%s is not in System32 directory" % BaseDllName)


if is_64bit():
    get_interrupt_vector = get_interrupt_vector_64
    find_PsLoadedModuleList = find_PsLoadedModuleList_64

else:
    get_interrupt_vector = get_interrupt_vector_32
    find_PsLoadedModuleList = find_PsLoadedModuleList_32

addr = get_interrupt_vector(0)
kernel_base = get_module_base(addr)
print("Kernel base is %s" % str(hex(kernel_base)))
PsLoadedModuleList = find_PsLoadedModuleList(kernel_base)
print("nt!PsLoadedModuleList is at %s" % str(hex(PsLoadedModuleList)))
walk_modulelist(PsLoadedModuleList, add_segment_callback)
walk_modulelist(PsLoadedModuleList, load_pdb_callback)
