// Decompiles the functions containing the given addresses into one C file.
// Usage (headless post-script): DecompileAt.java <out.c> <hex address>...
import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileResults;
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;
import java.io.PrintWriter;

public class DecompileAt extends GhidraScript {
  @Override
  public void run() throws Exception {
    String[] args = getScriptArgs();
    DecompInterface decomp = new DecompInterface();
    decomp.openProgram(currentProgram);
    try (PrintWriter out = new PrintWriter(args[0], "UTF-8")) {
      for (int i = 1; i < args.length; i++) {
        Address a = toAddr(args[i]);
        Function f = getFunctionContaining(a);
        if (f == null) {
          out.printf("// %s: no function%n%n", args[i]);
          continue;
        }
        DecompileResults r = decomp.decompileFunction(f, 120, monitor);
        out.printf("// ---- %s (contains %s) ----%n", f.getName(), args[i]);
        out.println(r.decompileCompleted() ? r.getDecompiledFunction().getC() : "// decompile failed");
      }
    }
  }
}
