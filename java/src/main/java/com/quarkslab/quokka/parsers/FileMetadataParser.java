package com.quarkslab.quokka.parsers;

import quokka.QuokkaOuterClass.Quokka.Meta.ISA;
import quokka.QuokkaOuterClass.Quokka.Meta.Compiler;
import quokka.QuokkaOuterClass.Quokka.Meta.CallingConvention;
import quokka.QuokkaOuterClass.Quokka.Meta.Hash.HashType;
import quokka.QuokkaOuterClass.Quokka.Meta.Endianess;
import quokka.QuokkaOuterClass.Quokka.AddressSize;
import ghidra.program.model.listing.Program;
import javax.lang.model.util.ElementScanner14;
import ghidra.program.model.lang.CompilerSpec;


/**
 * Retrieves from the ghidra analysis all the metadata needed by the Quokka protobuf
 */
public class FileMetadataParser {
    private Program program;

    // Metadata fields
    private String execName;
    private ISA arch;
    private Compiler compiler;
    private CallingConvention callConvention;
    private String hash;
    private HashType hashType;
    private Endianess endianess;
    private AddressSize address_size;
    private long baseAddr;

    public FileMetadataParser(Program program) {
        this.program = program;
    }

    /**
     * Run the analysis, extract all the informations needed from Ghidra
     */
    public void analyze() {
        this.execName = new File(this.program.getExecutablePath()).getName();

        // Ghidra uses a quad format like x86:LE:32:default
        String[] quad = this.program.getLanguageID().toString().split(":");
        assert quad.length == 4;
        this.arch = switch (quad[0].toLowerCase()) {
            case "x86" -> ISA.PROC_INTEL;
            case "arm" -> ISA.PROC_ARM;
            case "powerpc" -> ISA.PROC_PPC;
            case "mips" -> ISA.PROC_MIPS;
            case "dalvik" -> ISA.PROC_DALVIK;
            default -> ISA.PROC_UNK;
        };
        this.endianess = switch (quad[1]) {
            case "LE" -> Endianess.END_LE;
            case "BE" -> Endianess.END_BE;
            default -> Endianess.END_UNK;
        };
        this.address_size = switch (quad[2]) {
            case "32" -> AddressSize.ADDR_32;
            case "64" -> AddressSize.ADDR_64;
            default -> AddressSize.ADDR_UNK;
        };

        this.compiler = switch (this.program.getCompiler().toLowerCase()) {
            case "gcc" -> Compiler.COMP_GCC;
            case "visual studio" -> Compiler.COMP_MS;
            case "borland", "borland c++" -> Compiler.COMP_BC;
            case "delphi" -> Compiler.COMP_BP;
            // TODO add all the remaining supported compilers
            default -> Compiler.COMP_UNK;
        };

        var convention = this.program.getCompilerSpec().getDefaultCallingConvention();
        // TODO use null supported switch expression with java 21 (LTS)
        if (convention == null) {
            this.callConvention = CallingConvention.CC_UNK;
        } else {
            this.callConvention = switch (convention.getName()) {
                case CompilerSpec.CALLING_CONVENTION_cdecl -> CallingConvention.CC_CDECL;
                case CompilerSpec.CALLING_CONVENTION_stdcall -> CallingConvention.CC_STDCALL;
                case CompilerSpec.CALLING_CONVENTION_pascal -> CallingConvention.CC_PASCAL;
                case CompilerSpec.CALLING_CONVENTION_fastcall -> CallingConvention.CC_FASTCALL;
                case CompilerSpec.CALLING_CONVENTION_thiscall -> CallingConvention.CC_THISCALL;
                default -> CallingConvention.CC_UNK;
            };
        }

        this.hash = this.program.getExecutableSHA256();
        this.hashType = HashType.HASH_SHA256;
        if (this.hash == null) {
            this.hash = this.program.getExecutableMD5();
            this.hashType = HashType.HASH_MD5;
            if (this.hash == null) {
                this.hash = "";
                this.hashType = HashType.HASH_NONE;
            }
        }

        this.baseAddr = this.program.getImageBase().getOffset();
    }

    public String getExecName() {
        return this.execName;
    }

    public String getArch() {
        return this.arch;
    }

    public Compiler getCompiler() {
        return this.compiler;
    }

    public CallingConvention getCallConvention() {
        return this.callConvention;
    }

    public String getHash() {
        return this.hash;
    }

    public HashType getHashType() {
        return this.hashType;
    }

    public Endianess getEndianess() {
        return this.endianess;
    }

    public AddressSize getAddresSize() {
        return this.address_size;
    }

    public long getBaseAddr() {
        return this.baseAddr;
    }
}
