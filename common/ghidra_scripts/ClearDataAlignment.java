// Clears the "Alignment" data that follows data rather than code, so Ghidra's decompiler can finish
// the functions that use those addresses. rea-ghidra runs it after every auto-analysis.
// Usage (headless post-script): ClearDataAlignment.java
//
// Kaiju's "CERT Kaiju Disassembly Improvements" analyzer turns each run of zero bytes after a defined
// data item into Alignment (its source notes "If there's a reference to this address, it is
// probably NOT alignment!"). Where zero-filled variables are initialized memory, as in the data
// object of an LE executable that holds its bss, global variables become Alignment, and the
// decompiler runs until its timeout on any function that indexes into one (README, "Headless Ghidra
// from the shell"). The analyzer stays on for what it does well, finding code in the gaps between
// functions; padding after an instruction stays Alignment.
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.CodeUnit;
import ghidra.program.model.listing.Data;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.Listing;
import java.util.ArrayList;
import java.util.List;

public class ClearDataAlignment extends GhidraScript {
  @Override
  public void run() throws Exception {
    Listing listing = currentProgram.getListing();
    List<Data> afterData = new ArrayList<>();
    for (Data d : listing.getDefinedData(true)) {
      if (isAlignment(d) && !afterInstruction(listing, d.getAddress())) afterData.add(d);
    }
    long bytes = 0;
    for (Data d : afterData) {
      bytes += d.getLength();
      listing.clearCodeUnits(d.getMinAddress(), d.getMaxAddress(), false);
    }
    println("Alignment after data cleared: " + afterData.size() + " item(s), " + bytes + " bytes");
  }

  private static boolean isAlignment(CodeUnit cu) {
    return cu instanceof Data d && d.getDataType().getName().equals("Alignment");
  }

  /** Whether the code unit before an address, past other Alignment, is an instruction. */
  private static boolean afterInstruction(Listing listing, Address a) {
    CodeUnit before = listing.getCodeUnitBefore(a);
    while (isAlignment(before)) before = listing.getCodeUnitBefore(before.getAddress());
    return before instanceof Instruction;
  }
}
