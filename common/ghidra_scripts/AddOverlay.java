// Adds bytes of a file as an overlay memory block at its load address, so code loaded at run time
// over a region of the program (a PS1 overlay) sits beside it in its own address space and its
// calls into the program resolve; then disassembles and makes a function at the block's start
// (or the given entry) so analysis has a seed.
// Usage (headless pre-script): AddOverlay.java <file> <file offset> <length> <hex load address>
//   <block name> [hex entry]
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.mem.MemoryBlock;
import java.io.File;
import java.io.FileInputStream;
import java.io.InputStream;

public class AddOverlay extends GhidraScript {
  @Override
  public void run() throws Exception {
    String[] a = getScriptArgs();
    File file = new File(a[0]);
    long offset = Long.parseLong(a[1]);
    long length = Long.parseLong(a[2]);
    long load = Long.parseUnsignedLong(a[3].replaceFirst("^0[xX]", ""), 16);
    long entry = a.length > 5 ? Long.parseUnsignedLong(a[5].replaceFirst("^0[xX]", ""), 16) : load;
    Address address = currentProgram.getAddressFactory().getDefaultAddressSpace().getAddress(load);
    MemoryBlock block;
    try (InputStream in = new FileInputStream(file)) {
      in.skipNBytes(offset);
      block = currentProgram.getMemory().createInitializedBlock(a[4], address, in, length,
          monitor, true);
    }
    block.setPermissions(true, true, true);
    block.setSourceName(file.getName());
    Address start = block.getStart().add(entry - load);
    disassemble(start);
    if (getFunctionAt(start) == null) {
      createFunction(start, null);
    }
    println("AddOverlay: " + a[4] + " " + length + " bytes at " + block.getStart() + " (entry "
        + start + ")");
  }
}
