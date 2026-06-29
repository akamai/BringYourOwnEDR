#!/usr/bin/env python3
import struct
import sys
import os

IMAGE_SCN_CNT_INITIALIZED_DATA = 0x00000040
IMAGE_SCN_CNT_CODE = 0x00000020
IMAGE_SCN_MEM_EXECUTE = 0x20000000
IMAGE_SCN_MEM_READ = 0x40000000
IMAGE_SCN_MEM_WRITE = 0x80000000

def align(value, alignment):
    """Align a value to the specified alignment"""
    return (value + alignment - 1) & ~(alignment - 1)

def read_struct(data, offset, fmt):
    """Read a struct from data at offset"""
    size = struct.calcsize(fmt)
    return struct.unpack(fmt, data[offset:offset + size])

def write_struct(data, offset, fmt, *values):
    """Write a struct to data at offset"""
    packed = struct.pack(fmt, *values)
    data[offset:offset + len(packed)] = packed

def main():
    if len(sys.argv) != 3:
        print("Usage: {} <input_pe> <output_pe>".format(sys.argv[0]))
        print("  Adds overlay data as a new PE section so it gets mapped with SEC_IMAGE")
        sys.exit(1)

    input_path = sys.argv[1]
    output_path = sys.argv[2]

    print(f"[+] Reading PE file: {input_path}")
    with open(input_path, 'rb') as f:
        data = bytearray(f.read())

    # Parse DOS header
    if len(data) < 64:
        print("[-] File too small to be a valid PE")
        sys.exit(1)

    dos_magic, = read_struct(data, 0, '<H')
    if dos_magic != 0x5A4D:  # 'MZ'
        print("[-] Invalid DOS signature")
        sys.exit(1)

    pe_offset, = read_struct(data, 0x3C, '<I')
    
    # Check PE signature
    if len(data) < pe_offset + 4:
        print("[-] Invalid PE offset")
        sys.exit(1)
    
    pe_sig, = read_struct(data, pe_offset, '<I')
    if pe_sig != 0x4550:  # 'PE\0\0'
        print("[-] Invalid PE signature")
        sys.exit(1)

    # Parse FILE header (COFF header)
    file_header_offset = pe_offset + 4
    machine, num_sections, timestamp, symtab_ptr, num_syms, opt_hdr_size, characteristics = \
        read_struct(data, file_header_offset, '<HHIIIHH')
    
    print(f"[+] Current number of sections: {num_sections}")
    print(f"[+] Optional header size: {opt_hdr_size}")

    # Parse Optional header magic to determine if 32 or 64 bit
    opt_header_offset = file_header_offset + 20
    opt_magic, = read_struct(data, opt_header_offset, '<H')
    
    is_64bit = (opt_magic == 0x20b)
    print(f"[+] PE type: {'PE32+' if is_64bit else 'PE32'}")

    # Read SizeOfImage and SectionAlignment from optional header
    if is_64bit:
        # PE32+
        size_of_image, = read_struct(data, opt_header_offset + 56, '<I')
        section_alignment, = read_struct(data, opt_header_offset + 32, '<I')
        file_alignment, = read_struct(data, opt_header_offset + 36, '<I')
    else:
        # PE32
        size_of_image, = read_struct(data, opt_header_offset + 56, '<I')
        section_alignment, = read_struct(data, opt_header_offset + 32, '<I')
        file_alignment, = read_struct(data, opt_header_offset + 36, '<I')

    print(f"[+] SizeOfImage: 0x{size_of_image:X}")
    print(f"[+] SectionAlignment: 0x{section_alignment:X}")
    print(f"[+] FileAlignment: 0x{file_alignment:X}")

    # Find the section table
    section_table_offset = opt_header_offset + opt_hdr_size
    
    # Parse all sections
    sections = []
    last_section_end = 0
    max_virtual_end = 0
    
    print("[+] Setting all existing sections to RWX...")
    for i in range(num_sections):
        section_offset = section_table_offset + i * 40
        name = data[section_offset:section_offset + 8]
        virtual_size, virtual_address, size_of_raw_data, pointer_to_raw_data, \
        ptr_relocs, ptr_line_nums, num_relocs, num_line_nums, characteristics = \
            read_struct(data, section_offset + 8, '<IIIIIIHHI')
        
        # Update section characteristics to RWX
        new_characteristics = characteristics | IMAGE_SCN_MEM_EXECUTE | IMAGE_SCN_MEM_READ | IMAGE_SCN_MEM_WRITE
        write_struct(data, section_offset + 36, '<I', new_characteristics)
        
        section_name_str = name.rstrip(b'\x00').decode('ascii', errors='ignore')
        print(f"    Section {section_name_str}: 0x{characteristics:08X} -> 0x{new_characteristics:08X}")
        
        sections.append({
            'name': name,
            'virtual_size': virtual_size,
            'virtual_address': virtual_address,
            'size_of_raw_data': size_of_raw_data,
            'pointer_to_raw_data': pointer_to_raw_data,
            'characteristics': new_characteristics
        })
        
        section_end = pointer_to_raw_data + size_of_raw_data
        if section_end > last_section_end:
            last_section_end = section_end
        
        virtual_end = virtual_address + align(virtual_size, section_alignment)
        if virtual_end > max_virtual_end:
            max_virtual_end = virtual_end

    print(f"[+] Last section ends at file offset: 0x{last_section_end:X}")
    print(f"[+] Last virtual address: 0x{max_virtual_end:X}")
    print(f"[+] File size: 0x{len(data):X}")

    # Check if there's overlay data
    if len(data) <= last_section_end:
        print("[!] No overlay data found. File already correct.")
        with open(output_path, 'wb') as f:
            f.write(data)
        return

    overlay_size = len(data) - last_section_end
    print(f"[+] Overlay data size: 0x{overlay_size:X} ({overlay_size} bytes)")

    # Check if we have space for a new section header
    new_section_header_offset = section_table_offset + num_sections * 40
    first_section_raw = min(s['pointer_to_raw_data'] for s in sections if s['pointer_to_raw_data'] > 0)
    
    if new_section_header_offset + 40 > first_section_raw:
        print("[-] No space for new section header in PE headers")
        print("[-] You may need to use a PE editor to expand the header space first")
        sys.exit(1)

    print(f"[+] Space available for new section header at offset: 0x{new_section_header_offset:X}")

    # Create new section
    new_section_name = b'.overlay'
    new_virtual_address = align(max_virtual_end, section_alignment)
    new_virtual_size = overlay_size
    new_size_of_raw_data = align(overlay_size, file_alignment)
    new_pointer_to_raw_data = align(last_section_end, file_alignment)
    new_characteristics = IMAGE_SCN_CNT_CODE | IMAGE_SCN_MEM_EXECUTE | IMAGE_SCN_MEM_READ | IMAGE_SCN_MEM_WRITE

    print(f"[+] New section virtual address: 0x{new_virtual_address:X}")
    print(f"[+] New section virtual size: 0x{new_virtual_size:X}")
    print(f"[+] New section raw data pointer: 0x{new_pointer_to_raw_data:X}")
    print(f"[+] New section raw data size: 0x{new_size_of_raw_data:X}")
    print(f"[+] New section characteristics: 0x{new_characteristics:08X} (RWX)")

    # Move overlay data to aligned position if needed
    if new_pointer_to_raw_data != last_section_end:
        padding = new_pointer_to_raw_data - last_section_end
        print(f"[+] Adding {padding} bytes of padding before overlay data")
        data[last_section_end:last_section_end] = b'\x00' * padding

    # Pad to file alignment if needed
    if new_size_of_raw_data > overlay_size:
        padding = new_size_of_raw_data - overlay_size
        print(f"[+] Padding overlay data with {padding} bytes")
        data.extend(b'\x00' * padding)

    # Write new section header
    section_name_padded = new_section_name + b'\x00' * (8 - len(new_section_name))
    data[new_section_header_offset:new_section_header_offset + 8] = section_name_padded
    write_struct(data, new_section_header_offset + 8, '<IIIIIIHHI',
                 new_virtual_size, new_virtual_address, new_size_of_raw_data, 
                 new_pointer_to_raw_data, 0, 0, 0, 0, new_characteristics)

    # Update number of sections in FILE header
    write_struct(data, file_header_offset + 2, '<H', num_sections + 1)
    print(f"[+] Updated section count: {num_sections} -> {num_sections + 1}")

    # Update SizeOfImage in optional header
    new_size_of_image = align(new_virtual_address + new_virtual_size, section_alignment)
    if is_64bit:
        write_struct(data, opt_header_offset + 56, '<I', new_size_of_image)
    else:
        write_struct(data, opt_header_offset + 56, '<I', new_size_of_image)
    print(f"[+] Updated SizeOfImage: 0x{size_of_image:X} -> 0x{new_size_of_image:X}")

    # Write output file
    with open(output_path, 'wb') as f:
        f.write(data)
    
    print(f"[+] Successfully created: {output_path}")
    print(f"[+] File size: 0x{len(data):X} ({len(data)} bytes)")
    print("[+] Done! The overlay data is now in the .overlay section and will be mapped.")

if __name__ == '__main__':
    main()