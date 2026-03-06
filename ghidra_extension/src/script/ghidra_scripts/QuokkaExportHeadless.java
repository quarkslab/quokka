// Export Quokka protobuf file from headless Ghidra analysis.
//
// Usage with analyzeHeadless:
//   analyzeHeadless /tmp/proj Test \
//     -import /path/to/binary \
//     -scriptPath ghidra_extension/src/script/ghidra_scripts \
//     -postScript QuokkaExportHeadless.java \
//     --out=/tmp/output.quokka --mode=LIGHT
//
// @category Quokka
// @description Export Ghidra analysis to Quokka protobuf format

import com.quarkslab.quokka.ExportPipeline;
import ghidra.app.script.GhidraScript;
import quokka.QuokkaOuterClass.Quokka;

import java.io.File;

public class QuokkaExportHeadless extends GhidraScript {

    @Override
    protected void run() throws Exception {
        String outPath = null;
        String modeStr = "LIGHT";

        String[] args = getScriptArgs();
        for (String arg : args) {
            if (arg.startsWith("--out=")) {
                outPath = arg.substring(6);
            } else if (arg.startsWith("--mode=")) {
                modeStr = arg.substring(7);
            }
        }

        if (outPath == null) {
            String exePath = currentProgram.getExecutablePath();
            outPath = exePath + ".quokka";
        }

        Quokka.ExporterMeta.Mode mode;
        if ("SELF_CONTAINED".equalsIgnoreCase(modeStr)) {
            mode = Quokka.ExporterMeta.Mode.MODE_SELF_CONTAINED;
        } else {
            mode = Quokka.ExporterMeta.Mode.MODE_LIGHT;
        }

        File outputFile = new File(outPath);
        println("Quokka: exporting to " + outputFile.getAbsolutePath()
                + " (mode=" + modeStr + ")");

        ExportPipeline.export(currentProgram, outputFile, mode, monitor);

        println("Quokka export complete: " + outputFile.getAbsolutePath()
                + " (" + outputFile.length() + " bytes)");
    }
}
