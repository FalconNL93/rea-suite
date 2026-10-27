// Decompiles every function that references a defined string containing one of the given texts.
// Usage (headless post-script): DecompileXrefs.java <out.c> <text>...
import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileResults;
import ghidra.app.script.GhidraScript;
import ghidra.program.model.listing.Data;
import ghidra.program.model.listing.Function;
import ghidra.program.model.symbol.Reference;
import java.io.PrintWriter;
import java.util.TreeMap;

public class DecompileXrefs extends GhidraScript {
  @Override
  public void run() throws Exception {
    String[] args = getScriptArgs();
    TreeMap<Long, Function> found = new TreeMap<>();
    for (Data d : currentProgram.getListing().getDefinedData(true)) {
      if (!d.hasStringValue()) continue;
      String s = String.valueOf(d.getValue());
      boolean match = false;
      for (int i = 1; i < args.length; i++) match |= s.contains(args[i]);
      if (!match) continue;
      for (Reference r : getReferencesTo(d.getAddress())) {
        Function f = getFunctionContaining(r.getFromAddress());
        if (f != null) found.put(f.getEntryPoint().getOffset(), f);
      }
    }
    DecompInterface decomp = new DecompInterface();
    decomp.openProgram(currentProgram);
    try (PrintWriter out = new PrintWriter(args[0], "UTF-8")) {
      for (Function f : found.values()) {
        DecompileResults r = decomp.decompileFunction(f, 120, monitor);
        out.printf("// ---- %s @ %s ----%n", f.getName(), f.getEntryPoint());
        out.println(r.decompileCompleted() ? r.getDecompiledFunction().getC() : "// decompile failed");
      }
    }
  }
}
