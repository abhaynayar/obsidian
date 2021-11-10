#$ gcc main.c -o main

elf = open('./main', 'rb')
data = elf.read()

# EI_CLASS, EI_DATA, EI_VERSION, EI_OSABI, EI_ABIVERSION, and EI_PAD

magic = data[:4]        # 0x7f ELF
ei_class = data[5]      # 1 => 32-bit, 2 => 64-bit
ei_data  = data[6]      # 1 => little-endian, 2 => big-endian
ei_version = data[7]    # 1 => current ELF version. (always 1)
ei_osabi = data[8]      # 0 => UNIX System V ABI
ei_abiversion = data[9] # 0 => usually set to 0. (default)


