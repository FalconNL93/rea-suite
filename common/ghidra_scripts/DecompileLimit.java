// The decompiler's limit per function for the suite's scripts: REA_GHIDRA_DECOMPILE_TIMEOUT_SECONDS,
// the setting REA reads too (default in common/env.sh); Ghidra's own default when it is unset.
// Not a script itself: DecompileAt and DecompileXrefs call it.
import ghidra.app.decompiler.DecompileOptions;
import ghidra.app.decompiler.DecompileResults;

public class DecompileLimit {
  private DecompileLimit() {}

  /** Seconds to give one function. */
  public static int seconds() {
    String v = System.getenv("REA_GHIDRA_DECOMPILE_TIMEOUT_SECONDS");
    return v == null || v.isBlank() ? DecompileOptions.SUGGESTED_DECOMPILE_TIMEOUT_SECS : Integer.parseInt(v.trim());
  }

  /** The C of a finished decompile, else a comment that says why it stopped. */
  public static String text(DecompileResults r) {
    if (r.decompileCompleted()) return r.getDecompiledFunction().getC();
    if (r.isTimedOut()) {
      return "// decompile failed: over the " + seconds() + " s limit (REA_GHIDRA_DECOMPILE_TIMEOUT_SECONDS)";
    }
    String why = r.getErrorMessage() == null ? "" : r.getErrorMessage().trim().replaceAll("\\s+", " ");
    return "// decompile failed" + (why.isEmpty() ? "" : ": " + why);
  }
}
