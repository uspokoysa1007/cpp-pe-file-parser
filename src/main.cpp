#include <iostream>
#include <fstream>
#include <vector>
#include <string>
#include <iomanip>
#include <cmath>
#include <windows.h>

double CalculateEntropy(const uint8_t* data, size_t size) {
    if (size == 0) return 0.0;
    size_t count[256] = {0};
    for (size_t i = 0; i < size; ++i) {
        count[data[i]]++;
    }
    double entropy = 0.0;
    for (int i = 0; i < 256; ++i) {
        if (count[i] > 0) {
            double p = static_cast<double>(count[i]) / static_cast<double>(size);
            entropy -= p * (std::log(p) / std::log(2.0));
        }
    }
    return entropy;
}

const char* MachineToString(WORD machine) {
    switch (machine) {
        case IMAGE_FILE_MACHINE_AMD64: return "x86_64 (AMD64)";
        case IMAGE_FILE_MACHINE_I386:  return "x86 (Intel 386)";
        case IMAGE_FILE_MACHINE_ARM64: return "ARM64";
        case IMAGE_FILE_MACHINE_ARM:   return "ARM Thumb-2";
        default: return "Unknown Architecture";
    }
}

const char* SubsystemToString(WORD sub) {
    switch (sub) {
        case IMAGE_SUBSYSTEM_WINDOWS_GUI: return "Windows GUI";
        case IMAGE_SUBSYSTEM_WINDOWS_CUI: return "Windows Console (CUI)";
        case IMAGE_SUBSYSTEM_NATIVE:      return "Native Driver / Kernel";
        case IMAGE_SUBSYSTEM_EFI_APPLICATION: return "EFI Application";
        default: return "Other/Unknown";
    }
}

int main(int argc, char* argv[]) {
    std::string targetFile;
    if (argc > 1) {
        targetFile = argv[1];
    } else {
        char selfPath[MAX_PATH];
        GetModuleFileNameA(NULL, selfPath, MAX_PATH);
        targetFile = selfPath;
        std::cout << "[*] No file specified. Analyzing self: " << targetFile << "\n\n";
    }

    std::ifstream file(targetFile, std::ios::binary);
    if (!file) {
        std::cerr << "[-] Error opening file: " << targetFile << "\n";
        return 1;
    }

    file.seekg(0, std::ios::end);
    size_t fileSize = file.tellg();
    file.seekg(0, std::ios::beg);

    std::vector<uint8_t> buffer(fileSize);
    file.read(reinterpret_cast<char*>(buffer.data()), fileSize);

    if (fileSize < sizeof(IMAGE_DOS_HEADER)) {
        std::cerr << "[-] File too small to be a valid PE.\n";
        return 1;
    }

    auto dosHeader = reinterpret_cast<const IMAGE_DOS_HEADER*>(buffer.data());
    if (dosHeader->e_magic != IMAGE_DOS_SIGNATURE) {
        std::cerr << "[-] Invalid DOS signature (expected 'MZ').\n";
        return 1;
    }

    if (dosHeader->e_lfanew + sizeof(IMAGE_NT_HEADERS64) > fileSize) {
        std::cerr << "[-] Invalid e_lfanew offset.\n";
        return 1;
    }

    auto ntHeaders = reinterpret_cast<const IMAGE_NT_HEADERS64*>(buffer.data() + dosHeader->e_lfanew);
    if (ntHeaders->Signature != IMAGE_NT_SIGNATURE) {
        std::cerr << "[-] Invalid NT Signature (expected 'PE\\0\\0').\n";
        return 1;
    }

    bool is64 = (ntHeaders->OptionalHeader.Magic == IMAGE_NT_OPTIONAL_HDR64_MAGIC);
    
    std::cout << "========================================================\n";
    std::cout << "          WINDOWS PE FILE STATIC ANALYSIS               \n";
    std::cout << "========================================================\n";
    std::cout << "Target File   : " << targetFile << "\n";
    std::cout << "File Size     : " << fileSize << " bytes (" << std::fixed << std::setprecision(2) << (fileSize / 1024.0) << " KB)\n";
    std::cout << "Architecture  : " << MachineToString(ntHeaders->FileHeader.Machine) << "\n";
    std::cout << "Sections Count: " << ntHeaders->FileHeader.NumberOfSections << "\n";
    std::cout << "Format        : " << (is64 ? "PE32+ (64-bit)" : "PE32 (32-bit)") << "\n";
    std::cout << "Subsystem     : " << SubsystemToString(ntHeaders->OptionalHeader.Subsystem) << "\n";
    std::cout << "Entry Point   : 0x" << std::hex << std::uppercase << ntHeaders->OptionalHeader.AddressOfEntryPoint << std::dec << "\n";
    std::cout << "Image Base    : 0x" << std::hex << std::uppercase << ntHeaders->OptionalHeader.ImageBase << std::dec << "\n\n";

    std::cout << "--- [ SECTIONS & SHANNON ENTROPY ] ----------------------\n";
    std::cout << std::left << std::setw(10) << "Name" 
              << std::setw(12) << "VirtAddr" 
              << std::setw(12) << "VirtSize" 
              << std::setw(12) << "RawSize" 
              << std::setw(10) << "Entropy" 
              << "Status" << "\n";
    std::cout << std::string(68, '-') << "\n";

    const IMAGE_SECTION_HEADER* sectionHeader = nullptr;
    if (is64) {
        sectionHeader = IMAGE_FIRST_SECTION(ntHeaders);
    } else {
        auto nt32 = reinterpret_cast<const IMAGE_NT_HEADERS32*>(buffer.data() + dosHeader->e_lfanew);
        sectionHeader = IMAGE_FIRST_SECTION(nt32);
    }

    for (WORD i = 0; i < ntHeaders->FileHeader.NumberOfSections; ++i) {
        char secName[9] = {0};
        memcpy(secName, sectionHeader[i].Name, 8);

        double entropy = 0.0;
        if (sectionHeader[i].PointerToRawData + sectionHeader[i].SizeOfRawData <= fileSize && sectionHeader[i].SizeOfRawData > 0) {
            entropy = CalculateEntropy(buffer.data() + sectionHeader[i].PointerToRawData, sectionHeader[i].SizeOfRawData);
        }

        std::string status = "Normal";
        if (entropy > 7.2) {
            status = "SUSPICIOUS (Packed/Encrypted)";
        } else if (entropy < 1.0 && sectionHeader[i].SizeOfRawData > 0) {
            status = "Low Entropy (Zero-filled)";
        }

        std::cout << std::left << std::setw(10) << secName
                  << "0x" << std::hex << std::setw(10) << sectionHeader[i].VirtualAddress
                  << "0x" << std::hex << std::setw(10) << sectionHeader[i].Misc.VirtualSize
                  << "0x" << std::hex << std::setw(10) << sectionHeader[i].SizeOfRawData
                  << std::dec << std::fixed << std::setprecision(3) << std::setw(10) << entropy
                  << status << "\n";
    }
    std::cout << std::string(68, '-') << "\n";
    std::cout << "[+] Analysis complete.\n";
    return 0;
}
