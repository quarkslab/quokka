package com.quarkslab.quokka.util;

import ghidra.program.model.data.Array;
import ghidra.program.model.data.BitFieldDataType;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.DataTypeComponent;
import ghidra.program.model.data.FunctionDefinition;
import ghidra.program.model.data.ParameterDefinition;
import ghidra.program.model.data.Pointer;
import ghidra.program.model.data.Structure;
import ghidra.program.model.data.TypeDef;
import ghidra.program.model.data.Union;
import org.junit.Test;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNull;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

public class CTypeRendererTest {

    // ------------------------------------------------------------------
    // render() dispatch
    // ------------------------------------------------------------------

    @Test
    public void testRenderPrimitiveReturnsNull() {
        DataType dt = mock(DataType.class);
        assertNull(CTypeRenderer.render(dt));
    }

    // ------------------------------------------------------------------
    // Enum rendering
    // ------------------------------------------------------------------

    @Test
    public void testRenderEnum() {
        ghidra.program.model.data.Enum e = mock(ghidra.program.model.data.Enum.class);
        when(e.getDisplayName()).thenReturn("Color");
        when(e.getNames()).thenReturn(new String[]{"RED", "GREEN", "BLUE"});
        when(e.getValue("RED")).thenReturn(0L);
        when(e.getValue("GREEN")).thenReturn(1L);
        when(e.getValue("BLUE")).thenReturn(2L);

        String expected =
                "typedef enum Color {\n" +
                "    RED = 0,\n" +
                "    GREEN = 1,\n" +
                "    BLUE = 2\n" +
                "} Color;";
        assertEquals(expected, CTypeRenderer.render(e));
    }

    @Test
    public void testRenderEnumEmpty() {
        ghidra.program.model.data.Enum e = mock(ghidra.program.model.data.Enum.class);
        when(e.getDisplayName()).thenReturn("Empty");
        when(e.getNames()).thenReturn(new String[]{});

        assertEquals("typedef enum Empty {\n} Empty;", CTypeRenderer.render(e));
    }

    @Test
    public void testRenderEnumSingleValue() {
        ghidra.program.model.data.Enum e = mock(ghidra.program.model.data.Enum.class);
        when(e.getDisplayName()).thenReturn("Bool");
        when(e.getNames()).thenReturn(new String[]{"FALSE"});
        when(e.getValue("FALSE")).thenReturn(0L);

        String expected =
                "typedef enum Bool {\n" +
                "    FALSE = 0\n" +
                "} Bool;";
        assertEquals(expected, CTypeRenderer.render(e));
    }

    @Test
    public void testRenderEnumNegativeValue() {
        ghidra.program.model.data.Enum e = mock(ghidra.program.model.data.Enum.class);
        when(e.getDisplayName()).thenReturn("Signed");
        when(e.getNames()).thenReturn(new String[]{"NEG", "POS"});
        when(e.getValue("NEG")).thenReturn(-1L);
        when(e.getValue("POS")).thenReturn(1L);

        String expected =
                "typedef enum Signed {\n" +
                "    NEG = -1,\n" +
                "    POS = 1\n" +
                "} Signed;";
        assertEquals(expected, CTypeRenderer.render(e));
    }

    // ------------------------------------------------------------------
    // Struct rendering
    // ------------------------------------------------------------------

    @Test
    public void testRenderStruct() {
        DataType intType = mock(DataType.class);
        when(intType.getDisplayName()).thenReturn("int");

        DataTypeComponent comp = mock(DataTypeComponent.class);
        when(comp.getFieldName()).thenReturn("x");
        when(comp.getDataType()).thenReturn(intType);

        Structure s = mock(Structure.class);
        when(s.getDisplayName()).thenReturn("Point");
        when(s.getDefinedComponents()).thenReturn(new DataTypeComponent[]{comp});

        String expected =
                "struct Point {\n" +
                "    int x;\n" +
                "};";
        assertEquals(expected, CTypeRenderer.render(s));
    }

    @Test
    public void testRenderStructEmptyFieldNameFallback() {
        DataType byteType = mock(DataType.class);
        when(byteType.getDisplayName()).thenReturn("byte");

        DataTypeComponent comp = mock(DataTypeComponent.class);
        when(comp.getFieldName()).thenReturn(null);
        when(comp.getDefaultFieldName()).thenReturn("field_0");
        when(comp.getDataType()).thenReturn(byteType);

        Structure s = mock(Structure.class);
        when(s.getDisplayName()).thenReturn("Foo");
        when(s.getDefinedComponents()).thenReturn(new DataTypeComponent[]{comp});

        String expected =
                "struct Foo {\n" +
                "    byte field_0;\n" +
                "};";
        assertEquals(expected, CTypeRenderer.render(s));
    }

    @Test
    public void testRenderStructWithPointerField() {
        DataType intType = mock(DataType.class);
        when(intType.getDisplayName()).thenReturn("int");

        Pointer ptrType = mock(Pointer.class);
        when(ptrType.getDataType()).thenReturn(intType);

        DataTypeComponent comp = mock(DataTypeComponent.class);
        when(comp.getFieldName()).thenReturn("data");
        when(comp.getDataType()).thenReturn(ptrType);

        Structure s = mock(Structure.class);
        when(s.getDisplayName()).thenReturn("Node");
        when(s.getDefinedComponents()).thenReturn(new DataTypeComponent[]{comp});

        String expected =
                "struct Node {\n" +
                "    int *data;\n" +
                "};";
        assertEquals(expected, CTypeRenderer.render(s));
    }

    @Test
    public void testRenderStructWithArrayField() {
        DataType charType = mock(DataType.class);
        when(charType.getDisplayName()).thenReturn("char");

        Array arrType = mock(Array.class);
        when(arrType.getNumElements()).thenReturn(32);
        when(arrType.getDataType()).thenReturn(charType);

        DataTypeComponent comp = mock(DataTypeComponent.class);
        when(comp.getFieldName()).thenReturn("name");
        when(comp.getDataType()).thenReturn(arrType);

        Structure s = mock(Structure.class);
        when(s.getDisplayName()).thenReturn("Entry");
        when(s.getDefinedComponents()).thenReturn(new DataTypeComponent[]{comp});

        String expected =
                "struct Entry {\n" +
                "    char name[32];\n" +
                "};";
        assertEquals(expected, CTypeRenderer.render(s));
    }

    @Test
    public void testRenderStructWithStructMemberPrefix() {
        Structure innerStruct = mock(Structure.class);
        when(innerStruct.getDisplayName()).thenReturn("Inner");

        DataTypeComponent comp = mock(DataTypeComponent.class);
        when(comp.getFieldName()).thenReturn("child");
        when(comp.getDataType()).thenReturn(innerStruct);

        Structure s = mock(Structure.class);
        when(s.getDisplayName()).thenReturn("Outer");
        when(s.getDefinedComponents()).thenReturn(new DataTypeComponent[]{comp});

        String expected =
                "struct Outer {\n" +
                "    struct Inner child;\n" +
                "};";
        assertEquals(expected, CTypeRenderer.render(s));
    }

    // ------------------------------------------------------------------
    // Union rendering
    // ------------------------------------------------------------------

    @Test
    public void testRenderUnion() {
        DataType intType = mock(DataType.class);
        when(intType.getDisplayName()).thenReturn("int");

        DataType floatType = mock(DataType.class);
        when(floatType.getDisplayName()).thenReturn("float");

        DataTypeComponent comp1 = mock(DataTypeComponent.class);
        when(comp1.getFieldName()).thenReturn("i");
        when(comp1.getDataType()).thenReturn(intType);

        DataTypeComponent comp2 = mock(DataTypeComponent.class);
        when(comp2.getFieldName()).thenReturn("f");
        when(comp2.getDataType()).thenReturn(floatType);

        Union u = mock(Union.class);
        when(u.getDisplayName()).thenReturn("Value");
        when(u.getComponents()).thenReturn(new DataTypeComponent[]{comp1, comp2});

        String expected =
                "union Value {\n" +
                "    int i;\n" +
                "    float f;\n" +
                "};";
        assertEquals(expected, CTypeRenderer.render(u));
    }

    // ------------------------------------------------------------------
    // Typedef rendering
    // ------------------------------------------------------------------

    @Test
    public void testRenderTypedefPrimitive() {
        DataType intType = mock(DataType.class);
        when(intType.getDisplayName()).thenReturn("int");

        TypeDef td = mock(TypeDef.class);
        when(td.getDisplayName()).thenReturn("MYINT");
        when(td.getDataType()).thenReturn(intType);

        assertEquals("typedef int MYINT;", CTypeRenderer.render(td));
    }

    @Test
    public void testRenderTypedefPointer() {
        DataType intType = mock(DataType.class);
        when(intType.getDisplayName()).thenReturn("int");

        Pointer ptrType = mock(Pointer.class);
        when(ptrType.getDataType()).thenReturn(intType);

        TypeDef td = mock(TypeDef.class);
        when(td.getDisplayName()).thenReturn("PINT");
        when(td.getDataType()).thenReturn(ptrType);

        assertEquals("typedef int *PINT;", CTypeRenderer.render(td));
    }

    @Test
    public void testRenderTypedefArray() {
        DataType intType = mock(DataType.class);
        when(intType.getDisplayName()).thenReturn("int");

        Array arrType = mock(Array.class);
        when(arrType.getNumElements()).thenReturn(10);
        when(arrType.getDataType()).thenReturn(intType);

        TypeDef td = mock(TypeDef.class);
        when(td.getDisplayName()).thenReturn("IntArr");
        when(td.getDataType()).thenReturn(arrType);

        assertEquals("typedef int IntArr[10];", CTypeRenderer.render(td));
    }

    @Test
    public void testRenderTypedefStruct() {
        Structure structType = mock(Structure.class);
        when(structType.getDisplayName()).thenReturn("Foo");

        TypeDef td = mock(TypeDef.class);
        when(td.getDisplayName()).thenReturn("Foo_t");
        when(td.getDataType()).thenReturn(structType);

        assertEquals("typedef struct Foo Foo_t;", CTypeRenderer.render(td));
    }

    // ------------------------------------------------------------------
    // Pointer / Array standalone rendering
    // ------------------------------------------------------------------

    @Test
    public void testRenderPointer() {
        Pointer p = mock(Pointer.class);
        when(p.getDisplayName()).thenReturn("int *");

        assertEquals("int *", CTypeRenderer.render(p));
    }

    @Test
    public void testRenderArray() {
        Array a = mock(Array.class);
        when(a.getDisplayName()).thenReturn("int[10]");

        assertEquals("int[10]", CTypeRenderer.render(a));
    }

    // ------------------------------------------------------------------
    // fieldDecl edge cases
    // ------------------------------------------------------------------

    @Test
    public void testFieldDeclVoidPointer() {
        Pointer voidPtr = mock(Pointer.class);
        when(voidPtr.getDataType()).thenReturn(null);

        assertEquals("void *data", CTypeRenderer.fieldDecl("data", voidPtr));
    }

    @Test
    public void testFieldDeclDoublePointer() {
        DataType intType = mock(DataType.class);
        when(intType.getDisplayName()).thenReturn("int");

        Pointer innerPtr = mock(Pointer.class);
        when(innerPtr.getDataType()).thenReturn(intType);

        Pointer outerPtr = mock(Pointer.class);
        when(outerPtr.getDataType()).thenReturn(innerPtr);

        assertEquals("int **pp", CTypeRenderer.fieldDecl("pp", outerPtr));
    }

    @Test
    public void testFieldDeclPointerToArray() {
        DataType intType = mock(DataType.class);
        when(intType.getDisplayName()).thenReturn("int");

        Array arrType = mock(Array.class);
        when(arrType.getNumElements()).thenReturn(10);
        when(arrType.getDataType()).thenReturn(intType);

        Pointer ptrType = mock(Pointer.class);
        when(ptrType.getDataType()).thenReturn(arrType);

        assertEquals("int (*p)[10]", CTypeRenderer.fieldDecl("p", ptrType));
    }

    @Test
    public void testFieldDeclBitfield() {
        DataType intType = mock(DataType.class);
        when(intType.getDisplayName()).thenReturn("int");

        BitFieldDataType bf = mock(BitFieldDataType.class);
        when(bf.getBaseDataType()).thenReturn(intType);
        when(bf.getBitSize()).thenReturn(3);

        assertEquals("int flags : 3", CTypeRenderer.fieldDecl("flags", bf));
    }

    @Test
    public void testFieldDeclFuncPointer() {
        DataType voidType = mock(DataType.class);
        when(voidType.getDisplayName()).thenReturn("void");

        DataType intType = mock(DataType.class);
        when(intType.getDisplayName()).thenReturn("int");

        ParameterDefinition param = mock(ParameterDefinition.class);
        when(param.getDataType()).thenReturn(intType);
        when(param.getName()).thenReturn("n");

        FunctionDefinition fd = mock(FunctionDefinition.class);
        when(fd.getReturnType()).thenReturn(voidType);
        when(fd.getArguments()).thenReturn(new ParameterDefinition[]{param});

        Pointer fpType = mock(Pointer.class);
        when(fpType.getDataType()).thenReturn(fd);

        assertEquals("void (*callback)(int n)",
                CTypeRenderer.fieldDecl("callback", fpType));
    }

    @Test
    public void testFieldDeclFuncPointerNoParams() {
        DataType intType = mock(DataType.class);
        when(intType.getDisplayName()).thenReturn("int");

        FunctionDefinition fd = mock(FunctionDefinition.class);
        when(fd.getReturnType()).thenReturn(intType);
        when(fd.getArguments()).thenReturn(new ParameterDefinition[]{});

        Pointer fpType = mock(Pointer.class);
        when(fpType.getDataType()).thenReturn(fd);

        assertEquals("int (*fn)(void)",
                CTypeRenderer.fieldDecl("fn", fpType));
    }

    @Test
    public void testFieldDeclEnumPrefix() {
        ghidra.program.model.data.Enum enumType =
                mock(ghidra.program.model.data.Enum.class);
        when(enumType.getDisplayName()).thenReturn("Color");

        assertEquals("enum Color c", CTypeRenderer.fieldDecl("c", enumType));
    }

    @Test
    public void testFieldDeclUnionPrefix() {
        Union unionType = mock(Union.class);
        when(unionType.getDisplayName()).thenReturn("Val");

        assertEquals("union Val v", CTypeRenderer.fieldDecl("v", unionType));
    }

    @Test
    public void testFieldDeclMultiDimArray() {
        DataType intType = mock(DataType.class);
        when(intType.getDisplayName()).thenReturn("int");

        Array innerArr = mock(Array.class);
        when(innerArr.getNumElements()).thenReturn(4);
        when(innerArr.getDataType()).thenReturn(intType);

        Array outerArr = mock(Array.class);
        when(outerArr.getNumElements()).thenReturn(3);
        when(outerArr.getDataType()).thenReturn(innerArr);

        assertEquals("int m[3][4]", CTypeRenderer.fieldDecl("m", outerArr));
    }
}
