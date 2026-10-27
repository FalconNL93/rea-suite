// Writes every function Ghidra found as TSV: entry, size in bytes, name, thunk flag, callers count.
// Usage (headless post-script): ExportFunctions.java <out.tsv>
import ghidra.app.script.GhidraScript;
import ghidra.program.model.listing.Function;
import java.io.PrintWriter;

public class ExportFunctions extends GhidraScript {
  @Override
  public void run() throws Exception {
    try (PrintWriter out = new PrintWriter(getScriptArgs()[0], "UTF-8")) {
      out.println("entry\tsize\tname\tthunk\tcallers");
      for (Function f : currentProgram.getFunctionManager().getFunctions(true)) {
        out.printf("%08x\t%d\t%s\t%d\t%d%n", f.getEntryPoint().getOffset(), f.getBody().getNumAddresses(),
            f.getName(), f.isThunk() ? 1 : 0, f.getCallingFunctions(monitor).size());
      }
    }
  }
}
