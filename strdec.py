import struct, ida_hexrays, idautils
from ida_hexrays import *

IDENTIFIER = 'gkkaekgaEE'
filetype = idaapi.inf_get_filetype()
IS_ELF   = filetype == idc.FT_ELF
IS_PE    = filetype == idc.FT_PE
assert IS_ELF or IS_PE, "Only ELF and PE binaries are supported."
IS_64 = ida_ida.inf_is_64bit()
ITPs = [
    ITP_SEMI, ITP_COLON, ITP_CURLY1, ITP_CURLY2, ITP_BLOCK1, ITP_BLOCK2, ITP_ARG64, ITP_CASE, ITP_DO, ITP_ELSE, ITP_SIGN, ITP_BRACE1, ITP_BRACE2, ITP_INNER_LAST
]

def strdecrypt(enc, key):
    l = len(enc)
    dec = list(enc)
    for i in range(l):
        for f in [0, 8, 16, 24]:
            dec[i] = (dec[i] & 0xff) ^ ((key >> f) & 0xff)
        dec[i] = bytes([dec[i]])
        key = (key + 1) & 0xffffffff
    try:
        return b''.join(dec).decode()
    except:
        return None

def get_previous_instruction(insn):
    ea = idaapi.prev_head(insn, 0x10)
    assert idaapi.decode_insn(idaapi.insn_t(), ea)
    return ea

def is_mov_mnem(mnem):
    return mnem.lower() in ['mov',      # ELF (or PE)
                            'movups',   # PE
                            'lea']

def extract_word(addr):
    f = idaapi.get_qword if IS_64 else idaapi.get_dword
    return f(addr)
    
def is_valid_ptr(ptr):
    return bool(idc.get_segm_name(ptr))

def extract_key_and_encstr(xref):
    if not idaapi.decode_insn(idaapi.insn_t(), xref):
        print(f"[-] Something went wrong with decoding instruction @ 0x{xref:x}")
        return None, None
    
    # get function arguments
    enc_str_insn, key_insn = idaapi.get_arg_addrs(xref)
    # arg1 = pointer to encrypted string struct
    enc_string_ptr = get_operand_value(enc_str_insn, 1)
    # arg2 = XOR key
    key = get_operand_value(key_insn, 1)
    if key < 0 or enc_string_ptr < 0:
        return None, None

    if get_operand_type(enc_str_insn, 1) == ida_ua.o_reg:
        # if second argument is a register
        # we need to get its value from previous instructions
        target_reg_id = get_operand_value(enc_str_insn, 1)
        register_assigned = False
        prev = enc_str_insn
        while not register_assigned:
            prev = get_previous_instruction(prev)
            # get mnemonic
            mnem = print_insn_mnem(prev)
            # get destination operand
            op0 = get_operand_value(prev, 0)
            # get source operand
            op1 = get_operand_value(prev, 1)
            # if our target register is assigned a valid pointer, we are good to go
            if is_mov_mnem(mnem) and op0 == target_reg_id and is_valid_ptr(op1):
                enc_string_ptr = op1
                register_assigned = True

    off = 0x08 if IS_64 else 0x04
    enc_str_length = extract_word(enc_string_ptr)
    enc_str_object_ptr = extract_word(enc_string_ptr + off)
    if is_valid_ptr(enc_str_object_ptr):
        enc_str = idaapi.get_bytes(enc_str_object_ptr, enc_str_length)
    else:
        # sometimes the struct is: Length | Length | Data
        # and not: Length | Pointer | Data
        enc_str = idaapi.get_bytes(enc_string_ptr + off + off, enc_str_length)

    return enc_str, key

def set_decrypted_string_as_comment(addr, comm):
    func_decomp = ida_hexrays.decompile(addr)
    
    tloc = ida_hexrays.treeloc_t()
    tloc.ea = addr
    
    # bruteforce ITP since ITP_SEMI, ITP_COLON fail most of the times
    for itp in ITPs:
        tloc.itp = itp
        func_decomp.set_user_cmt(tloc, comm.strip())           # set comment in pseudocode
        idc.set_cmt(addr, comm.strip(), True)                  # set comment in disassembly
        func_decomp.save_user_cmts()
        func_decomp.__str__()
        if not func_decomp.has_orphan_cmts():
            break
        func_decomp.del_orphan_cmts()
    else:
        raise RuntimeError(f"A comment could not be set @ 0x{addr:x}")

def main():
    symbols = list(idautils.Functions())
    print(f'[+] Loaded {len(symbols)} symbols')

    strenc_symbol = next(filter(lambda f: IDENTIFIER in idaapi.get_name(f), symbols), None)

    if not strenc_symbol:
        print(f'[-] The strenc function could not be found. Make sure its name contains "{IDENTIFIER}".')
        return

    xrefs = [
        x.frm for x in idautils.XrefsTo(strenc_symbol)
        if idaapi.getseg(x.frm) == idaapi.getseg(strenc_symbol)
    ]

    print(f'[+] Found {len(xrefs)} references to {idaapi.get_name(strenc_symbol)}')

    for i, xref in enumerate(xrefs):
        enc, key = extract_key_and_encstr(xref)
        if not (enc and key):
            print(f'[-] Failed to extract enc string or key @ 0x{xref:x}')
            continue
        
        dec = strdecrypt(enc, key)
        if not dec:
            print(f'[-] Failed to decrypt @ 0x{xref:x}')
            continue
        
        set_decrypted_string_as_comment(xref, dec)
        print(f'[{i+1}/{len(xrefs)}] Comment: {dec.encode()} set @ 0x{xref:x}')



if __name__ == '__main__':
    main()