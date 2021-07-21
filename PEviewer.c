// gcc -o PEviewer ./PEviewer.c
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

char *DOS_HEADER_NAMES[31] = {
    "e_magic", 
    "e_cblp", 
    "e_cp", 
    "e_crlc", 
    "e_cparhdr", 
    "e_minalloc", 
    "e_maxalloc", 
    "e_ss", 
    "e_sp", 
    "e_csum",
    "e_ip", 
    "e_cs", 
    "e_lfarlc", 
    "e_ovno", 
    "e_res[0]", 
    "e_res[1]", 
    "e_res[2]", 
    "e_res[3]", 
    "e_oemid", 
    "e_oeminfo",
    "e_res2[0]", 
    "e_res2[1]", 
    "e_res2[2]", 
    "e_res2[3]", 
    "e_res2[4]", 
    "e_res2[5]", 
    "e_res2[6]", 
    "e_res2[7]", 
    "e_res2[8]", 
    "e_res2[9]",
    "e_lfanew"
};

char *IMAGE_FILE_HEADER_NAMES[7] = {
    "Machine", 
    "NumberOfSections", 
    "TimeDateStamp", 
    "PointerToSymbolTable", 
    "NumberOfSymbols",
    "SizeOfOptionalHeader", 
    "Characteristics"
};

int IMAGE_FILE_HEADER_SIZES[7] = {2, 2, 4, 4, 4, 2, 2};

char *IMAGE_FILE_HEADER_CHARACTERISTICS[16] = {
    "IMAGE_FILE_RELOCS_STRIPPED",               // 0x0001
    "IMAGE_FILE_EXECUTABLE_IMAGE",              // 0x0002
    "IMAGE_FILE_LINE_NUMS_STRIPPED",            // 0x0004
    "IMAGE_FILE_LOCAL_SYMS_STRIPPED",           // 0x0008
    "IMAGE_FILE_AGGRESSIVE_WS_TRIM",            // 0x0010
    "IMAGE_FILE_LARGE_ADDRESS_AWARE",           // 0x0020
    "",
    "IMAGE_FILE_BYTES_REVERSED_LO",             // 0x0080
    "IMAGE_FILE_32BIT_MACHINE",                 // 0x0100
    "IMAGE_FILE_DEBUG_STRIPPED",                // 0x0200
    "IMAGE_FILE_REMOVABLE_RUN_FROM_SWAP",       // 0x0400
    "IMAGE_FILE_NET_RUN_FROM_SWAP",             // 0x0800
    "IMAGE_FILE_SYSTEM",                        // 0x1000
    "IMAGE_FILE_DLL",                           // 0x2000
    "IMAGE_FILE_UP_SYSTEM_ONLY",                // 0x4000
    "IMAGE_FILE_BYTES_REVERSED_HI"              // 0x8000
};

char *IMAGE_OPTIONAL_HEADER_NAMES[30] = {
    "Magic", 
    "MajorLinkerVersion", 
    "MinorLinkerVersion", 
    "SizeOfCode", 
    "SizeOfInitializedData",
    "SizeOfUninitializedData", 
    "AddressOfEntryPoint", 
    "BaseOfCode", 
    "BaseOfData", 
    "ImageBase",
    "SectionAlignment", 
    "FileAlignment", 
    "MajorOperatingSystemVersion", 
    "MinorOperatingSystemVersion", 
    "MajorImageVersion",
    "MinorImageVersion", 
    "MajorSubsystemVersion", 
    "MinorSubsystemVersion", 
    "Win32VersionValue", 
    "SizeOfImage",
    "SizeOfHeaders", 
    "CheckSum", 
    "Subsystem", 
    "DllCharacteristics", 
    "SizeOfStackReserve",
    "SizeOfStackCommit", 
    "SizeOfHeapReserve", 
    "SizeOfHeapCommit", 
    "LoaderFlags", 
    "NumberOfRvaAndSizes"
};

int IMAGE_OPTIONAL_HEADER_SIZES[30] = {
    2, 1, 1, 4, 4, 4, 4, 4, 4, 4, 4, 4, 2, 2, 2, 
    2, 2, 2, 4, 4, 4, 4, 2, 2, 4, 4, 4, 4, 4, 4
};

char *DATA_DIRECTORY_NAMES[16] = {
    "EXPORT Directory",
    "IMPORT Directory",
    "RESOURCE Directory",
    "EXCEPTION Directory",
    "SECURITY Directory",
    "BASERELOC Directory",
    "DEBUG Directory",
    "COPYRIGHT Directory",
    "GLOBALPTR Directory",
    "TLS Directory",
    "LOAD_CONFIG Directory",
    "BOUND_IMPORT Directory",
    "IAT Directory",
    "DELAY_IMPORT Directory",
    "COM_DESCRIPTOR Directory",
    "Reserved Directory"
};

char *IMAGE_SECTION_HEADER_NAMES[10] = {
    "Name",
    "PhysicalAddress/VirtualSize",
    "VirtualAddress",
    "SizeOfRawData",
    "PointerToRawData",
    "PointerToRelocations",
    "PointerToLinenumbers",
    "NumberOfRelocations",
    "NumberOfLinenumbers",
    "Characteristics"
};

int IMAGE_SECTION_HEADER_SIZES[10] = {
    8, 4, 4, 4, 4, 4, 4, 2, 2, 4
};

char *IMAGE_SECTION_HEADER_CHARACTERISTICS[6] = {
    "IMAGE_SCN_CNT_CODE",                   // 0x00000020
    "IMAGE_SCN_CNT_INITIALIZED_DATA",       // 0x00000040
    "IMAGE_SCN_CNT_UNINITIALIZED_DATA",     // 0x00000080
    "IMAGE_SCN_MEM_EXECUTE",                // 0x20000000
    "IMAGE_SCN_MEM_READ",                   // 0x40000000
    "IMAGE_SCN_MEM_WRITE"                   // 0x80000000
};

char *IMAGE_IMPORT_DESCRIPTOR_NAMES[5] = {
    "OriginalFirstThunk",
    "TimeDateStamp",
    "ForwarderChain",
    "Name",
    "FirstThunk"
};

int IMAGE_IMPORT_DESCRIPTOR_SIZES[5] = { 4, 4, 4, 4, 4 };

void printNbytes(char*, int);

int main(int argc, char *argv[])
{
    FILE* fp;
    char buf[0x500];
    char data[0x500];
    int offset = 0;
    int prev_offset;
    int NT_HEADER_OFFSET = 0;
    int NUMBER_OF_SECTIONS = 0;
    int NUMBER_OF_RVA_AND_SIZES = 0;
    int IMAGE_SECTION_HEADER_OFFSET;
    int IMPORT_DIRECTORY_RVA;
    int VirtualAddress;
    int PointerToRawData;
    int IMAGE_IMPORT_DESCRIPTOR_OFFSET;
    int NAME_RVA, NAME_OFFSET;
    int IMAGE_IMPORT_BY_NAME_OFFSET; // INT
    int IMPORT_ADDRESS_TABLE_OFFSET; // IAT 
    char ch1[4], ch2[4];

    if (argc != 2)
    {
        printf("Usage: ./PEviewer <filename>\n");
        exit(0);
    }

    fp = fopen(argv[1], "rb");
    if (fp == NULL)
    {
        printf("File open error\n");
        exit(0);
    }

    /* DOS Header */
    printf("[+] DOS Header\n");
    fread(buf, sizeof(char), 0x40, fp);

    memcpy(data, buf, 2);
    data[2] = 0;
    // printf("┌ 0x%08X\t%-10s\t%02X%02X\t%s\t/* DOS Signature */\n", offset, DOS_HEADER_NAMES[0], *data, *(data+1), data);
    printf("┌ 0x%08X\t%-10s\t%04X\t%s\t/* DOS Signature */\n", offset, DOS_HEADER_NAMES[0], *(int*)data, data);
    offset += 2;

    for (int i=1; i<30; i++)
    {
        memcpy(data, buf+offset, 2);
        data[2] = 0;
        printf("├ 0x%08X\t%-10s\t", offset, DOS_HEADER_NAMES[i]);
        printNbytes(data, 2);
        printf("\n");

        offset += 2;
    }

    memcpy(data, buf+offset, 4);
    data[4] = 0;
    NT_HEADER_OFFSET = *(int*)data;
    printf("└ 0x%08X\t%-10s\t", offset, DOS_HEADER_NAMES[30]);
    printNbytes(data, 4);
    printf("\n\n");
    offset += 4;

    /* NT Header */
    printf("[+] NT Header\n");
    fseek(fp, NT_HEADER_OFFSET, SEEK_SET);
    fread(buf, sizeof(char), 0xf8, fp);
    offset = NT_HEADER_OFFSET;

    /* IMAGE_FILE_HEADER */
    printf("┌─ IMAGE_FILE_HEADER\n");
    memcpy(data, buf, 4);
    data[4] = 0;
    printf("│  ├ 0x%08X\t%-25s\t%08X\t%s\n", offset, "Signature", *(int*)data, data);
    offset += 4;

    for (int i=0; i<6; i++)
    {
        memcpy(data, buf+(offset-NT_HEADER_OFFSET), IMAGE_FILE_HEADER_SIZES[i]);
        data[IMAGE_FILE_HEADER_SIZES[i]] = 0;
        printf("│  ├ 0x%08X\t%-25s\t", offset, IMAGE_FILE_HEADER_NAMES[i]);
        printNbytes(data, IMAGE_FILE_HEADER_SIZES[i]);
        printf("\n");
        offset += IMAGE_FILE_HEADER_SIZES[i];
    }
    memcpy(data, buf+(offset-NT_HEADER_OFFSET), IMAGE_FILE_HEADER_SIZES[6]);
    data[IMAGE_FILE_HEADER_SIZES[6]] = 0;
    printf("│  └ 0x%08X\t%-25s\t", offset, IMAGE_FILE_HEADER_NAMES[6]);
    printNbytes(data, IMAGE_FILE_HEADER_SIZES[6]);
    printf("\n");
    offset += IMAGE_FILE_HEADER_SIZES[6];

    // *(int*)data = 0xffff;
    for (int i=0; i<15; i++)
    {
        if (*(int*)data & (1 << i))
        {
            if (*(int*)data / (1<<(i+1)))
                printf("│\t\t├");
            else
                printf("│\t\t└");

            printf(" %s\n", IMAGE_FILE_HEADER_CHARACTERISTICS[i]);
        
        }
    }
    printf("│\n");

    /* IMAGE_OPTIONAL_HEADER32 */
    printf("└─ IMAGE_OPTIONAL_HEADER32\n");
    for (int i=0; i<29; i++)
    {
        memcpy(data, buf+(offset-NT_HEADER_OFFSET), IMAGE_OPTIONAL_HEADER_SIZES[i]);
        data[IMAGE_OPTIONAL_HEADER_SIZES[i]] = 0;
        printf("   ├ 0x%08X\t%-25s\t", offset, IMAGE_OPTIONAL_HEADER_NAMES[i]);
        printNbytes(data, IMAGE_OPTIONAL_HEADER_SIZES[i]);
        printf("\n");
        offset += IMAGE_OPTIONAL_HEADER_SIZES[i];
    }
    memcpy(data, buf+(offset-NT_HEADER_OFFSET), IMAGE_OPTIONAL_HEADER_SIZES[29]);
    data[IMAGE_OPTIONAL_HEADER_SIZES[29]] = 0;
    printf("   └ 0x%08X\t%-25s\t", offset, IMAGE_OPTIONAL_HEADER_NAMES[29]);
    printNbytes(data, IMAGE_OPTIONAL_HEADER_SIZES[29]);
    printf("\n");
    NUMBER_OF_RVA_AND_SIZES = *(int*)data;
    offset += IMAGE_OPTIONAL_HEADER_SIZES[29];

    for (int i=0; i<NUMBER_OF_RVA_AND_SIZES-1; i++)
    {
        printf("\t\t├ 0x%08X\t%s\n", offset, DATA_DIRECTORY_NAMES[i]);

        printf("\t\t│\t\t├ RVA\t");
        memcpy(data, buf+(offset-NT_HEADER_OFFSET), 4);
        printNbytes(data, 4);
        offset += 4;
        printf("\n");

        printf("\t\t│\t\t└ Size\t");
        memcpy(data, buf+(offset-NT_HEADER_OFFSET), 4);
        printNbytes(data, 4);
        offset += 4;
        printf("\n\t\t│\n");
    }

    printf("\t\t└ 0x%08X\t%s\n", offset, DATA_DIRECTORY_NAMES[15]);

    printf("\t\t\t\t├ RVA\t");
    memcpy(data, buf+(offset-NT_HEADER_OFFSET), 4);
    printNbytes(data, 4);
    offset += 4;
    printf("\n");

    printf("\t\t\t\t└ Size\t");
    memcpy(data, buf+(offset-NT_HEADER_OFFSET), 4);
    printNbytes(data, 4);
    offset += 4;
    printf("\n\n");

    /* IMAGE_SECTION_HEADER */
    printf("[+] IMAGE_SECTION_HEADER\n");
    IMAGE_SECTION_HEADER_OFFSET = offset;
    prev_offset = offset;
    fseek(fp, NT_HEADER_OFFSET+6, SEEK_SET);
    fread(&NUMBER_OF_SECTIONS, sizeof(char), 2, fp);



    for (int n=1; n<=NUMBER_OF_SECTIONS; n++)
    {
        fseek(fp, prev_offset, SEEK_SET);
        fread(buf, sizeof(char), 0x38, fp);

        memcpy(data, buf+(offset-prev_offset), IMAGE_SECTION_HEADER_SIZES[0]);
        if (n == 1 && n == NUMBER_OF_SECTIONS)
        {
            strcpy(ch1, "─");
            strcpy(ch2, " ");
        }
        else if (n == 1)
        {
            strcpy(ch1, "┌");
            strcpy(ch2, "│");
        }
        else if (n == NUMBER_OF_SECTIONS)
        {
            strcpy(ch1, "└");
            strcpy(ch2, " ");
        }
        else
        {
            strcpy(ch1, "├");
            strcpy(ch2, "│");
        }

        printf("%s─ IMAGE_SECTION_HEADER %s\n", ch1, data);
        printf("%s  ├ 0x%08X\t%-30s\t", ch2, offset, IMAGE_SECTION_HEADER_NAMES[0]);
        printNbytes(data, IMAGE_SECTION_HEADER_SIZES[0]);
        printf("\t%s\n", data);
        offset += IMAGE_SECTION_HEADER_SIZES[0];

        for (int i=1; i<9; i++)
        {
            printf("%s  ├ 0x%08X\t%-30s\t", ch2, offset, IMAGE_SECTION_HEADER_NAMES[i]);
            memcpy(data, buf+(offset-prev_offset), IMAGE_SECTION_HEADER_SIZES[i]);
            printNbytes(data, IMAGE_SECTION_HEADER_SIZES[i]);
            printf("\n");
            offset += IMAGE_SECTION_HEADER_SIZES[i];
        }
    
        printf("%s  └ 0x%08X\t%-30s\t", ch2, offset, IMAGE_SECTION_HEADER_NAMES[9]);
        memcpy(data, buf+(offset-prev_offset), IMAGE_SECTION_HEADER_SIZES[9]);
        printNbytes(data, IMAGE_SECTION_HEADER_SIZES[9]);
        printf("\n");
        offset += IMAGE_SECTION_HEADER_SIZES[9];

        for (int i=0x20, count=0; i!=0x00000000; i<<=1, count++)
        {
            if (*(int*)data & i)
            {
                if (((*(int*)data/i) == 1))
                    printf("%s\t\t└ ", ch2);
                else
                    printf("%s\t\t├ ", ch2);
                printf("%s\n", IMAGE_SECTION_HEADER_CHARACTERISTICS[count]);
            }

            if (i == 0x00000080)
                i = 0x10000000;
        }
        prev_offset = offset;
        printf("%s\n", ch2);
    }
    
    /* Import Address Table */
    printf("[+] IMAGE_IMPORT_DESCRIPTOR\n");
    offset = NT_HEADER_OFFSET + 0x80;
    fseek(fp, offset, SEEK_SET);
    fread(data, sizeof(char), 4, fp);
    IMPORT_DIRECTORY_RVA = *(int*)data;

    offset = IMAGE_SECTION_HEADER_OFFSET + 12;
    fseek(fp, offset, SEEK_SET);
    fread(data, sizeof(char), 12, fp);
    VirtualAddress = *(int*)data;
    PointerToRawData = *(int*)(data+8);

    IMAGE_IMPORT_DESCRIPTOR_OFFSET = IMPORT_DIRECTORY_RVA - VirtualAddress + PointerToRawData;
    offset = IMAGE_IMPORT_DESCRIPTOR_OFFSET;

    /* IMAGE_IMPORT_DESCRIPTOR */
    while (1) 
    {
        prev_offset = offset;
        fseek(fp, offset, SEEK_SET);
        fread(buf, sizeof(char), 24, fp);
    
        memcpy(data, buf+12, 4);
        if ((*(int*)data) == 0)
            break;

        NAME_OFFSET = *(int*)data - VirtualAddress + PointerToRawData;
        fseek(fp, NAME_OFFSET, SEEK_SET);
        fread(data, sizeof(char), 20, fp);
        printf("    %s\n", data);

        memcpy(data, buf+(offset-prev_offset), IMAGE_IMPORT_DESCRIPTOR_SIZES[0]);
        printf("    ┌ 0x%08X %-20s\t", offset, IMAGE_IMPORT_DESCRIPTOR_NAMES[0]);
        printNbytes(data, 4);
        printf("\n");
        IMAGE_IMPORT_BY_NAME_OFFSET = *(int*)data - VirtualAddress + PointerToRawData;
        offset += IMAGE_IMPORT_DESCRIPTOR_SIZES[0];

        for (int i=1; i<4; i++)
        {
            memcpy(data, buf+(offset-prev_offset), IMAGE_IMPORT_DESCRIPTOR_SIZES[i]);
            printf("    ├ 0x%08X %-20s\t", offset, IMAGE_IMPORT_DESCRIPTOR_NAMES[i]);
            printNbytes(data, 4);
            printf("\n");
            offset += IMAGE_IMPORT_DESCRIPTOR_SIZES[i];
        }
        memcpy(data, buf+(offset-prev_offset), IMAGE_IMPORT_DESCRIPTOR_SIZES[4]);
        printf("    ├ 0x%08X %-20s\t", offset, IMAGE_IMPORT_DESCRIPTOR_NAMES[4]);
        printNbytes(data, 4);
        printf("\n");
        IMPORT_ADDRESS_TABLE_OFFSET = *(int*)data - VirtualAddress + PointerToRawData;
        printf("    │\n");
        printf("    └─────────── Import Address Table\n");

        int off = IMAGE_IMPORT_BY_NAME_OFFSET;
        int off2;
        int ordinal;
        int count = 0;
        while (1)
        {
            fseek(fp, off, SEEK_SET);
            fread(data, sizeof(char), 4, fp); // *(int*)data == Hint/Name RVA
            if (*(int*)data == 0)
                break;

            printf("\t\t");
            off2 = *(int*)data - VirtualAddress + PointerToRawData; // tmp = Hint/Name File offset

            fread(data, sizeof(char), 4, fp);
            if (*(int*)data == 0)
            {
                if (count == 0)
                    printf("─ ");
                else
                    printf("└ ");
            }
            else if (count == 0)
                printf("┌ ");
            else
                printf("├ ");

            printf("0x%08X ", IMPORT_ADDRESS_TABLE_OFFSET+count*4);
            fseek(fp, off2, SEEK_SET);
            fread(&ordinal, sizeof(char), 2, fp);
            fread(data, sizeof(char), 0x20, fp);
            printf("%-30s\t(ordinal : %04X)\n", data, ordinal);

            off += 4;
            count++;
        }

        offset += IMAGE_IMPORT_DESCRIPTOR_SIZES[4];
        printf("\n");
    }

    fclose(fp);
}

void printNbytes(char* data, int len)
{
    //for (int i=0; i<len; i++)
    for (int i=len-1; i>=0; i--)
        printf("%02X", *(char*)(data+i) & 0xff);
}