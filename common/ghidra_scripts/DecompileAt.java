// Decompiles the functions containing the given addresses into one C file. An address outside
// every function gets one created there (in memory only when the project is opened -readOnly).
// Instructions Ghidra could not decode in a function are counted in its header: the decompile
// stops at them. Each function gets REA_GHIDRA_DECOMPILE_TIMEOUT_SECONDS (DecompileLimit.java).
// Usage (headless post-script): DecompileAt.java <out.c> <hex address>...
import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileResults;
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.listing.Bookmark;
import ghidra.program.model.listing.BookmarkManager;
import ghidra.program.model.listing.BookmarkType;
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
        boolean created = false;
        if (f == null && getInstructionAt(a) != null) {
          f = createFunction(a, null);
          created = f != null;
        }
        if (f == null) {
          out.printf("// %s: no function%n%n", args[i]);
          continue;
        }
        DecompileResults r = decomp.decompileFunction(f, DecompileLimit.seconds(), monitor);
        out.printf("// ---- %s @ %s (contains %s%s) ----%n", f.getName(), f.getEntryPoint(), args[i],
            created ? "; function created here" : "");
        int undecoded = 0;
        BookmarkManager marks = currentProgram.getBookmarkManager();
        AddressSetView errors = marks.getBookmarkAddresses(BookmarkType.ERROR).intersect(f.getBody());
        for (Address e : errors.getAddresses(true)) {
          for (Bookmark b : marks.getBookmarks(e, BookmarkType.ERROR)) {
            if (b.getCategory().equals("Bad Instruction")) undecoded++;
          }
        }
        if (undecoded > 0) {
          out.printf("// limit: %d instruction(s) in this function Ghidra could not decode%n", undecoded);
        }
        out.println(DecompileLimit.text(r));
      }
    }
  }
}
