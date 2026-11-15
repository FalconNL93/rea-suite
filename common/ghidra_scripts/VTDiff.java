// Function-by-function diff with Ghidra's Version Tracking correlators, headless.
// Usage: analyzeHeadless <proj> <name> -process <any other program> -noanalysis -readOnly
//          -scriptPath <dir> -postScript VTDiff.java /old.exe /new.exe
// Both builds must be analyzed in the project already. Neither may be the processed program:
// Version Tracking refuses a program the headless run holds open (LockException).
// Each source function gets the first correlator (strongest first) that matched it. Matches are
// accepted as they are taken, since the reference correlators grow out of accepted matches.
// @category VersionTracking
import ghidra.feature.vt.AbstractGhidraVersionTrackingScript;
import ghidra.feature.vt.api.main.VTMatch;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Program;
import java.util.*;

public class VTDiff extends AbstractGhidraVersionTrackingScript {
  private static final String[] ORDER = {
    "Exact Function Bytes Match",
    "Exact Function Instructions Match",
    "Exact Function Mnemonics Match",
    "Exact Symbol Name Match",
    "Combined Function and Data Reference Match",
    "Function Reference Match",
    "BSim Function Matching",
  };

  @Override
  protected void run() throws Exception {
    createVersionTrackingSession(getScriptArgs()[0], getScriptArgs()[1]);
    Program src = getSourceProgram(), dst = getDestinationProgram();
    {
      println("correlators available: " + getProgramCorrelators());
      Map<String, String> verdict = new TreeMap<>();
      Set<String> dstMatched = new HashSet<>();
      for (String c : ORDER) {
        if (!getProgramCorrelators().contains(c)) { println("missing correlator: " + c); continue; }
        runCorrelator(c);
        for (VTMatch m : getMatchesFromLastRunCorrelator()) {
          Function s = getSourceFunction(m), d = getDestinationFunction(m);
          if (s == null || d == null) continue;
          String key = s.getEntryPoint() + " " + s.getName();
          if (verdict.containsKey(key) || dstMatched.contains(d.getEntryPoint().toString())) continue;
          verdict.put(key, String.format("-> %s %s  [%s, score %.3f, len %d->%d]",
              d.getEntryPoint(), d.getName(), c, m.getSimilarityScore().getScore(),
              s.getBody().getNumAddresses(), d.getBody().getNumAddresses()));
          dstMatched.add(d.getEntryPoint().toString());
          try { m.getAssociation().setAccepted(); } catch (Exception e) { /* conflicting: left open */ }
        }
      }
      for (Function s : src.getFunctionManager().getFunctions(true)) {
        if (s.isExternal() || s.isThunk()) continue;
        String key = s.getEntryPoint() + " " + s.getName();
        println("VTDIFF " + key + " " + verdict.getOrDefault(key, "-> UNMATCHED"));
      }
      for (Function d : dst.getFunctionManager().getFunctions(true)) {
        if (d.isExternal() || d.isThunk() || dstMatched.contains(d.getEntryPoint().toString())) continue;
        println("VTDIFF only in new: " + d.getEntryPoint() + " " + d.getName());
      }
    }
  }
}
