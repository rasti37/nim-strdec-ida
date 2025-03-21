import struct, ida_hexrays, idautils

IDENTIFIER = 'gkkaekgaEE'
filetype = idaapi.inf_get_filetype()
IS_ELF   = filetype == idc.FT_ELF
IS_PE    = filetype == idc.FT_PE
assert IS_ELF or IS_PE, "Only ELF and PE binaries are supported."
IS_64 = idaapi.get_inf_structure().is_64bit()

def strdecrypt(enc, l, key):
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
    ea = idaapi.prev_head(insn.ea, 0x10)
    prev_insn = idaapi.insn_t()
    assert idaapi.decode_insn(prev_insn, ea)
    return prev_insn

def get_pointer_type(addr):
    l = 1
    while True:
        addr = idaapi.get_qword(addr)
        seg = idaapi.getseg(addr)
        if not seg:
            break
        l += 1
    return l

def is_mov_mnem(mnem):
    return mnem in [
                    'mov',      # ELF (or PE)
                    'movups',   # PE
                   ]

def extract_word(addr):
    f = idaapi.get_qword if IS_64 else idaapi.get_dword
    return f(addr)
    
def is_source_operand_ptr_to_rdata(insn):
    if is_mov_mnem(insn.get_canon_mnem()):
        ptr = insn.Op2.addr
        # make sure it's a single pointer
        if get_pointer_type(ptr) == 1:
            if idaapi.get_segm_name(idaapi.getseg(ptr)) in ['.rdata', '.rodata', '__const']:
                return ptr

def extract_enc_string_from_current_insn(insn):
    prev = insn
    off = 0x08 if IS_64 else 0x04
    # hopefully, the enc string will be one in one of the previous 100 instructions
    for _ in range(50):
        prev = get_previous_instruction(prev)
        ptr_to_data_segment = is_source_operand_ptr_to_rdata(prev)
        if ptr_to_data_segment:
            enc_str_length = extract_word(ptr_to_data_segment)
            enc_str_object_ptr = extract_word(ptr_to_data_segment + off)
            enc_str = idaapi.get_bytes(enc_str_object_ptr + off, enc_str_length)
            return enc_str_length, enc_str

    raise ValueError(f"Something went really wrong trying to extract enc string for call @ 0x{insn.ea:x}")

def extract_key_from_current_insn(insn):
    prev = insn
    # hopefully, the key will be one in one of the previous 100 instructions
    for _ in range(50):
        prev = get_previous_instruction(prev)
        if is_mov_mnem(prev.get_canon_mnem().lower()):
            if IS_64:
                # mov <reg>, <key>
                if prev.Op1.type == idaapi.o_reg and prev.Op2.type == ida_ua.o_imm:
                    return prev.Op2.value
            else:
                # mov dword ptr [esp+8], <key>
                if prev.Op1.type == idaapi.o_displ and prev.Op1.dtype == ida_ua.o_mem and prev.Op2.type == ida_ua.o_imm:
                    return prev.Op2.value

    raise ValueError(f"Something went really wrong trying to extract the key for call @ 0x{insn.ea:x}")

def extract_key_and_encstr(xref):
    current_insn = idaapi.insn_t()
    if not idaapi.decode_insn(current_insn, xref):
        print(f"[-] Something went wrong with decoding instruction @ 0x{xref:x}")
        return None, None, None
    
    l, enc_string = extract_enc_string_from_current_insn(current_insn)
    key = extract_key_from_current_insn(current_insn)
    
    return enc_string, l, key

def set_decrypted_string_as_comment(addr, comm):
    func_decomp = ida_hexrays.decompile(addr)
    
    tloc = ida_hexrays.treeloc_t()
    tloc.ea = addr
    tloc.itp = ida_hexrays.ITP_SEMI
    
    func_decomp.set_user_cmt(tloc, comm)           # set comment in pseudocode
    idc.set_cmt(addr, comm, True)                  # set comment in disassembly
    
    func_decomp.save_user_cmts()
    ida_hexrays.mark_cfunc_dirty(addr)
    func_decomp.refresh_func_ctext()

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
        enc, l, key = extract_key_and_encstr(xref)
        if not (enc and l and key):
            print(f'[-] Failed to extract enc string or key @ 0x{xref:x}')
            continue
        dec = strdecrypt(enc, l, key)
        if not dec:
            print(f'[-] Failed to decrypt @ 0x{xref:x}')
            continue
        set_decrypted_string_as_comment(xref, dec)
        print(f'[{i+1}/{len(xrefs)}] Comment: "{dec}" set @ 0x{xref:x}')



if __name__ == '__main__':
    main()