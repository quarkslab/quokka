package com.quarkslab.quokka.export;

import com.quarkslab.quokka.ExportContext;
import com.quarkslab.quokka.compat.Compat;
import com.quarkslab.quokka.util.CallingConventionMapper;
import com.quarkslab.quokka.util.HashUtil;
import com.quarkslab.quokka.util.IsaMapper;
import ghidra.program.model.listing.Program;
import quokka.QuokkaOuterClass.Quokka;

import java.io.File;

/**
 * Phase 1: Export ExporterMeta and Meta messages.
 * Populates ISA, endianness, hash, backend, address_size, calling_convention.
 */
public class MetaExporter {

    private MetaExporter() {}

    public static void export(ExportContext ctx, Quokka.Builder builder)
            throws Exception {
        Program program = ctx.getProgram();

        // ExporterMeta
        builder.setExporterMeta(Quokka.ExporterMeta.newBuilder()
                .setMode(ctx.getMode())
                .setVersion("1.0.0"));

        // Meta
        Quokka.Meta.Builder meta = Quokka.Meta.newBuilder();

        // Executable name: basename only
        String execPath = program.getExecutablePath();
        String baseName = execPath;
        int lastSlash = execPath.lastIndexOf('/');
        if (lastSlash >= 0) {
            baseName = execPath.substring(lastSlash + 1);
        }
        int lastBackslash = baseName.lastIndexOf('\\');
        if (lastBackslash >= 0) {
            baseName = baseName.substring(lastBackslash + 1);
        }
        meta.setExecutableName(baseName);

        // ISA
        String procName = program.getLanguage().getProcessor().toString();
        meta.setIsa(IsaMapper.map(procName));

        // Endianness
        if (program.getLanguage().isBigEndian()) {
            meta.setEndianess(Quokka.Meta.Endianess.END_BE);
        } else {
            meta.setEndianess(Quokka.Meta.Endianess.END_LE);
        }

        // Address size
        int ptrSize = program.getDefaultPointerSize();
        if (ptrSize == 8) {
            meta.setAddressSize(Quokka.AddressSize.ADDR_64);
        } else if (ptrSize == 4) {
            meta.setAddressSize(Quokka.AddressSize.ADDR_32);
        } else {
            meta.setAddressSize(Quokka.AddressSize.ADDR_UNK);
        }

        // Hash: SHA-256 of original binary
        File binaryFile = new File(execPath);
        String hashValue = HashUtil.computeHash(program, binaryFile);
        meta.setHash(Quokka.Meta.Hash.newBuilder()
                .setHashType(Quokka.Meta.Hash.HashType.HASH_SHA256)
                .setHashValue(hashValue));

        // Backend
        meta.setBackend(Quokka.Meta.Backend.newBuilder()
                .setName(Quokka.Meta.Backend.Disassembler.DISASS_GHIDRA)
                .setVersion(Compat.getGhidraVersion()));

        // Calling convention
        try {
            String ccName = program.getCompilerSpec()
                    .getDefaultCallingConvention().getName();
            meta.setCallingConvention(CallingConventionMapper.map(ccName));
        } catch (Exception e) {
            meta.setCallingConvention(Quokka.CallingConvention.CC_UNK);
        }

        builder.setMeta(meta);
    }
}
