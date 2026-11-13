// PS3 PPU program before auto-analysis: sets r2 to the module's TOC over every executable block (the
// ELFv1 ABI reads every global through r2, so the decompiler resolves them only with its value), and
// starts a function at each seed address (the code pointers of the OPDs, the exports and the import
// stubs, found by `rea-suite ps3 analyze`), so a stripped program is not left to Ghidra's guesses.
// Prints one line "Ps3Prepare: toc=0x... blocks=N seeds=N created=N" for the caller's summary.
// Usage (headless pre-script): Ps3Prepare.java <toc in hex, 0 for none> <seeds.txt: one hex address a line>
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.lang.Register;
import ghidra.program.model.listing.ProgramContext;
import ghidra.program.model.mem.MemoryBlock;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;

public class Ps3Prepare extends GhidraScript {
  @Override
  public void run() throws Exception {
    String[] args = getScriptArgs();
    long toc = Long.parseUnsignedLong(args[0].replaceFirst("^0x", ""), 16);
    int blocks = 0;
    if (toc != 0) {
      ProgramContext context = currentProgram.getProgramContext();
      Register r2 = currentProgram.getRegister("r2");
      for (MemoryBlock block : currentProgram.getMemory().getBlocks()) {
        if (block.isExecute() && block.isInitialized()) {
          context.setValue(r2, block.getStart(), block.getEnd(), BigInteger.valueOf(toc));
          blocks++;
        }
      }
    }
    int seeds = 0;
    int created = 0;
    for (String line : Files.readAllLines(Path.of(args[1]), StandardCharsets.UTF_8)) {
      line = line.strip();
      if (line.isEmpty()) {
        continue;
      }
      seeds++;
      Address at = toAddr(line);
      if (at == null || getFunctionAt(at) != null || !currentProgram.getMemory().contains(at)) {
        continue;
      }
      if (getInstructionAt(at) == null && !disassemble(at)) {
        continue;
      }
      if (createFunction(at, null) != null) {
        created++;
      }
    }
    println(String.format("Ps3Prepare: toc=0x%x blocks=%d seeds=%d created=%d", toc, blocks, seeds, created));
  }
}
