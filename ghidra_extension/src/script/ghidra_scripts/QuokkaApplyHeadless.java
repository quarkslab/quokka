// Apply recorded Quokka edits back to a headless Ghidra project.
//
// Usage with analyzeHeadless:
//   analyzeHeadless /tmp/proj Test \
//     -process binary_name \
//     -scriptPath ghidra_extension/src/script/ghidra_scripts \
//     -postScript QuokkaApplyHeadless.java "--quokka=/tmp/input.quokka"
//
// @category Quokka
// @description Apply Quokka protobuf edits to the current Ghidra program

import ghidra.app.cmd.function.ApplyFunctionSignatureCmd;
import ghidra.app.script.GhidraScript;
import ghidra.app.util.cparser.C.CParser;
import ghidra.app.util.parser.FunctionSignatureParser;
import ghidra.program.model.address.Address;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.DataTypeConflictHandler;
import ghidra.program.model.data.DataTypeManager;
import ghidra.program.model.data.FunctionDefinitionDataType;
import ghidra.program.model.listing.CodeUnit;
import ghidra.program.model.listing.Data;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Listing;
import ghidra.program.model.symbol.SourceType;
import ghidra.program.model.symbol.Symbol;
import ghidra.program.model.symbol.SymbolTable;
import ghidra.util.data.DataTypeParser;
import quokka.QuokkaOuterClass.Quokka;

import java.io.File;
import java.io.FileInputStream;

public class QuokkaApplyHeadless extends GhidraScript {

    private int errors = 0;

    @Override
    protected void run() throws Exception {
        String quokkaPath = null;

        for (String arg : getScriptArgs()) {
            if (arg.startsWith("--quokka=")) {
                quokkaPath = arg.substring(9);
            }
        }

        if (quokkaPath == null) {
            throw new IllegalArgumentException("--quokka=<file> is required");
        }

        File inputFile = new File(quokkaPath);
        println("Quokka: applying edits from " + inputFile.getAbsolutePath());

        Quokka quokka;
        try (FileInputStream in = new FileInputStream(inputFile)) {
            quokka = Quokka.parseFrom(in);
        }

        int transactionId = currentProgram.startTransaction("Apply Quokka edits");
        boolean commit = false;
        try {
            applyTypes(quokka);
            applyFunctions(quokka);
            applyData(quokka);
            commit = true;
        } finally {
            currentProgram.endTransaction(transactionId, commit);
        }

        println("Quokka apply complete: " + errors + " error(s)");
    }

    private Address addressFor(int segmentIndex, long segmentOffset, Quokka quokka) {
        long base = quokka.getSegments(segmentIndex).getVirtualAddr();
        return currentProgram.getAddressFactory()
                .getDefaultAddressSpace()
                .getAddress(base + segmentOffset);
    }

    private void applyTypes(Quokka quokka) {
        for (Quokka.Type type : quokka.getTypesList()) {
            if (!type.getIsNew()) {
                continue;
            }

            String cStr = "";
            String name = "";
            if (type.hasCompositeType()) {
                cStr = type.getCompositeType().getCStr();
                name = type.getCompositeType().getName();
            } else if (type.hasEnumType()) {
                cStr = type.getEnumType().getCStr();
                name = type.getEnumType().getName();
            }

            if (cStr.isBlank()) {
                error("create type " + name + " (no c_str available)");
                continue;
            }

            try {
                DataTypeManager dtm = currentProgram.getDataTypeManager();
                CParser parser = new CParser(dtm);
                DataType dt = parser.parse(cStr);
                if (dt == null) {
                    dt = parser.getLastDataType();
                }
                if (dt == null) {
                    error("create type " + name + " (parser returned no type)");
                    continue;
                }
                dtm.addDataType(dt, DataTypeConflictHandler.DEFAULT_HANDLER);
                ok("create type " + name);
            } catch (Exception e) {
                error("create type " + name + ": " + e.getMessage());
            }
        }
    }

    private void applyFunctions(Quokka quokka) {
        for (Quokka.Function pbFunction : quokka.getFunctionsList()) {
            Quokka.Function.FunctionEdits edits = pbFunction.getEdits();
            if (!edits.getNameSet()
                    && !edits.getPrototypeSet()
                    && edits.getCommentsCount() == 0
                    && edits.getEdgesCount() == 0) {
                continue;
            }

            Address entry = addressFor(
                    pbFunction.getSegmentIndex(),
                    pbFunction.getSegmentOffset(),
                    quokka);
            Function function = currentProgram.getFunctionManager()
                    .getFunctionAt(entry);
            if (function == null) {
                error("function not found at " + entry);
                continue;
            }

            if (edits.getNameSet()) {
                try {
                    function.setName(pbFunction.getName(), SourceType.USER_DEFINED);
                    ok("set name of function at " + entry + " to "
                            + pbFunction.getName());
                } catch (Exception e) {
                    error("set name of function at " + entry + ": "
                            + e.getMessage());
                }
            }

            if (edits.getPrototypeSet()) {
                applyPrototype(function, pbFunction.getPrototype());
            }

            if (edits.getCommentsCount() > 0) {
                try {
                    function.setComment(joinComments(
                            pbFunction.getCommentsList(),
                            edits.getCommentsList()));
                    ok("set comment of function at " + entry);
                } catch (Exception e) {
                    error("set comment of function at " + entry + ": "
                            + e.getMessage());
                }
            }

            if (edits.getEdgesCount() > 0) {
                error("function edge apply-back is not implemented for Ghidra at "
                        + entry);
            }
        }
    }

    private void applyPrototype(Function function, String prototype) {
        try {
            DataTypeManager dtm = currentProgram.getDataTypeManager();
            FunctionSignatureParser parser =
                    new FunctionSignatureParser(dtm, null);
            FunctionDefinitionDataType signature = parser.parse(null, prototype);
            ApplyFunctionSignatureCmd cmd = new ApplyFunctionSignatureCmd(
                    function.getEntryPoint(),
                    signature,
                    SourceType.USER_DEFINED);

            if (!cmd.applyTo(currentProgram, monitor)) {
                error("set prototype of function at " + function.getEntryPoint()
                        + ": " + cmd.getStatusMsg());
                return;
            }
            ok("set prototype of function at " + function.getEntryPoint()
                    + " to " + prototype);
        } catch (Exception e) {
            error("set prototype of function at " + function.getEntryPoint()
                    + ": " + e.getMessage());
        }
    }

    private void applyData(Quokka quokka) {
        for (Quokka.Data pbData : quokka.getDataList()) {
            Quokka.Data.DataEdits edits = pbData.getEdits();
            if (!edits.getNameSet()
                    && edits.getTypeStr().isEmpty()
                    && edits.getCommentsCount() == 0) {
                continue;
            }

            Address address = addressFor(
                    pbData.getSegmentIndex(),
                    pbData.getSegmentOffset(),
                    quokka);

            if (edits.getNameSet()) {
                applyDataName(address, pbData.getName());
            }

            if (!edits.getTypeStr().isEmpty()) {
                applyDataType(address, edits.getTypeStr());
            }

            if (edits.getCommentsCount() > 0) {
                try {
                    currentProgram.getListing().setComment(
                            address,
                            CodeUnit.PLATE_COMMENT,
                            joinComments(pbData.getCommentsList(),
                                    edits.getCommentsList()));
                    ok("set comment of data at " + address);
                } catch (Exception e) {
                    error("set comment of data at " + address + ": "
                            + e.getMessage());
                }
            }
        }
    }

    private void applyDataName(Address address, String name) {
        try {
            SymbolTable symbolTable = currentProgram.getSymbolTable();
            Symbol symbol = symbolTable.getPrimarySymbol(address);
            if (symbol != null) {
                if (!name.equals(symbol.getName())) {
                    symbol.setName(name, SourceType.USER_DEFINED);
                }
            } else {
                symbolTable.createLabel(address, name, SourceType.USER_DEFINED);
            }
            ok("set name of data at " + address + " to " + name);
        } catch (Exception e) {
            error("set name of data at " + address + ": " + e.getMessage());
        }
    }

    private void applyDataType(Address address, String typeText) {
        try {
            DataType dataType = parseDataType(typeText);
            if (dataType == null) {
                error("set type of data at " + address
                        + " (unable to parse " + typeText + ")");
                return;
            }

            Listing listing = currentProgram.getListing();
            Data existing = listing.getDataAt(address);
            if (existing != null) {
                listing.clearCodeUnits(
                        address,
                        existing.getMaxAddress(),
                        false);
            }
            listing.createData(address, dataType);
            ok("set type of data at " + address + " to " + typeText);
        } catch (Exception e) {
            error("set type of data at " + address + ": " + e.getMessage());
        }
    }

    private DataType parseDataType(String typeText) throws Exception {
        DataTypeManager dtm = currentProgram.getDataTypeManager();
        try {
            DataTypeParser parser = new DataTypeParser(
                    dtm,
                    dtm,
                    null,
                    DataTypeParser.AllowedDataTypes.ALL);
            return parser.parse(typeText);
        } catch (Exception ignored) {
            DataType dt = new CParser(dtm).parse(typeText);
            if (dt != null) {
                return currentProgram.getDataTypeManager()
                        .addDataType(dt, DataTypeConflictHandler.DEFAULT_HANDLER);
            }
            return null;
        }
    }

    private String joinComments(
            java.util.List<String> comments,
            java.util.List<Integer> indexes) {
        StringBuilder builder = new StringBuilder();
        for (int i = 0; i < indexes.size(); i++) {
            if (i > 0) {
                builder.append('\n');
            }
            builder.append(comments.get(indexes.get(i)));
        }
        return builder.toString();
    }

    private void ok(String message) {
        println("[ok] " + message);
    }

    private void error(String message) {
        errors++;
        println("[x] " + message);
    }
}
