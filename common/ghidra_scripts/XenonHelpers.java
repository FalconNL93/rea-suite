// Xbox 360 (Xenon) register save/restore helpers: find them by their instruction pattern, name them
// and keep them returning, so the functions that call them in their prologue and epilogue decompile
// in full. Also reports the instructions Ghidra could not decode (VMX128 has no Sleigh support).
// Usage (headless):
//   -preScript  XenonHelpers.java prepare <summary.json>  before auto-analysis (import)
//   -postScript XenonHelpers.java repair  <summary.json>  after analysis, or on a project analyzed
//                                                         without `prepare` (works in -readOnly)
//
// The helpers (__savegprlr_14..31, __restgprlr_*, __savefpr_*, __restfpr_*, __savevmx_*,
// __restvmx_*) are one routine per register class with an entry point per register; each entry
// falls through into the next. Ghidra splits them into 4-byte functions that fall into another
// function, and "Non-Returning Functions - Discovered" then marks them noreturn and clears the code
// after every call: callers end at their prologue. Both modes name the entries and give them a
// call-fixup without effect (a program spec extension): that analyzer skips a target whose fixup
// falls through (FindNoReturnFunctionsAnalyzer.hasCallFixupWithFallThrough), the decompiler
// drops the calls, and the analyzer stays on for the truly non-returning functions. `prepare`
// also defines the functions a PE image's .pdata lists; `repair` undoes what an analysis without
// `prepare` did to the call sites.
import ghidra.app.cmd.function.CreateFunctionCmd;
import ghidra.app.script.GhidraScript;
import ghidra.program.database.SpecExtension;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Bookmark;
import ghidra.program.model.listing.BookmarkType;
import ghidra.program.model.listing.FlowOverride;
import ghidra.program.model.symbol.FlowType;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.mem.MemoryAccessException;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.model.symbol.Reference;
import ghidra.program.model.symbol.SourceType;
import java.io.PrintWriter;
import java.util.ArrayList;
import java.util.Iterator;
import java.util.List;
import java.util.TreeMap;
import java.util.TreeSet;

public class XenonHelpers extends GhidraScript {
  static final int BLR = 0x4E800020;
  static final int STW_R12 = 0x9181FFF8; // stw r12,-0x8(r1)
  static final int LWZ_R12 = 0x8181FFF8; // lwz r12,-0x8(r1)
  static final int MTLR_R12 = 0x7D8803A6;
  static final String FIXUP = "xenon_register_helper";
  // Saving or restoring callee-saved registers changes nothing the caller's decompile models.
  static final String FIXUP_XML = "<callfixup name=\"" + FIXUP + "\"><pcode><body><![CDATA[\n"
      + "  r0 = r0;\n]]></body></pcode></callfixup>";

  final TreeMap<Address, String> helpers = new TreeMap<>();
  Memory mem;

  int word(Address a) throws MemoryAccessException {
    return mem.getInt(a, true);
  }

  // std rS,ds(r1) / ld rS,ds(r1) / stfd fS,d(r12) / lfd fS,d(r12): register S at offset -8*(32-S)
  // (GPRs end at -0x10, the slot below holds LR).
  static int dsForm(int opcode, int reg, int base, int offset) {
    return (opcode << 26) | (reg << 21) | (base << 16) | (offset & 0xFFFF);
  }

  // Walks back from the last store/load of register 31 while the previous word stores/loads the
  // previous register; every word of the run is an entry point.
  void chain(Address last, int opcode, int base, int top, String name) throws Exception {
    Address a = last;
    for (int reg = 31; reg >= 14; reg--) {
      if (word(a) != dsForm(opcode, reg, base, -8 * (top - reg))) break;
      helpers.put(a, name + reg);
      if (reg == 14) break;
      a = a.subtract(4);
    }
  }

  static boolean vmxStoreOrLoad(int w) {
    if (((w >>> 16) & 0x1F) != 11 || ((w >>> 11) & 0x1F) != 12) return false;
    int op = w >>> 26;
    if (op == 31) return ((w >>> 1) & 0x3FF) == 231 || ((w >>> 1) & 0x3FF) == 103; // stvx, lvx
    return op == 4 && ((w & 0xFC0007F3) == 0x100001C3 || (w & 0xFC0007F3) == 0x100000C3);
  }

  static boolean vmxStore(int w) {
    return w >>> 26 == 31 ? ((w >>> 1) & 0x3FF) == 231 : (w & 0x7F3) == 0x1C3;
  }

  static int vmxRegister(int w) {
    int reg = (w >>> 21) & 0x1F;
    return w >>> 26 == 4 ? reg | ((w & 0xC) << 3) : reg; // VMX128: two more bits of VD128
  }

  void find() throws Exception {
    for (MemoryBlock block : mem.getBlocks()) {
      if (!block.isExecute() || !block.isInitialized()) continue;
      Address end = block.getEnd().subtract(3);
      for (Address a = block.getStart(); a.compareTo(end) < 0; a = a.add(4)) {
        monitor.checkCancelled();
        int w = word(a);
        Address next = a.add(4);
        if (w == STW_R12 && a.compareTo(block.getStart()) > 0 && word(next) == BLR) {
          chain(a.subtract(4), 62, 1, 33, "__savegprlr_");
        } else if (w == LWZ_R12 && word(next) == MTLR_R12 && a.compareTo(block.getStart()) > 0) {
          chain(a.subtract(4), 58, 1, 33, "__restgprlr_");
        } else if (w == BLR && a.compareTo(block.getStart()) > 0) {
          Address prev = a.subtract(4);
          int p = word(prev);
          if (p == dsForm(54, 31, 12, -8)) chain(prev, 54, 12, 32, "__savefpr_");
          else if (p == dsForm(50, 31, 12, -8)) chain(prev, 50, 12, 32, "__restfpr_");
          else vmxChain(prev, block.getStart());
        }
      }
    }
  }

  // VMX: pairs of `li r11,offset` and stvx/lvx(128) vN,r11,r12 ending in blr.
  void vmxChain(Address op, Address blockStart) throws Exception {
    while (op.subtract(4).compareTo(blockStart) >= 0) {
      int w = word(op);
      Address li = op.subtract(4);
      if (!vmxStoreOrLoad(w) || (word(li) >>> 16) != 0x3960) return; // addi r11,r0,imm
      helpers.put(li, (vmxStore(w) ? "__savevmx_" : "__restvmx_") + vmxRegister(w));
      if (li.subtract(4).compareTo(blockStart) < 0) return;
      op = li.subtract(4);
    }
  }

  // Highest first: each new function's body then stops at the entry above it.
  int mark() throws Exception {
    int created = 0;
    for (Address a : helpers.descendingKeySet()) {
      Function f = getFunctionAt(a);
      if (f == null) {
        if (getInstructionAt(a) == null) disassemble(a);
        if (new CreateFunctionCmd(a).applyTo(currentProgram, monitor)) created++;
        f = getFunctionAt(a);
      }
      if (f == null) continue;
      if (f.getSymbol().getSource() == SourceType.DEFAULT
          || f.getName().startsWith("FUN_")
          || f.getName().startsWith("Function_")) {
        f.setName(helpers.get(a), SourceType.ANALYSIS);
      }
      f.setNoReturn(false);
      f.setCallFixup(FIXUP);
    }
    return created;
  }

  // Calls left without a fall-through by an earlier analysis get it back; the callers' bodies grow
  // over the re-disassembled code.
  int[] repair() throws Exception {
    TreeSet<Address> callers = new TreeSet<>();
    int calls = 0;
    for (Address a : helpers.keySet()) {
      Iterator<Reference> refs = currentProgram.getReferenceManager().getReferencesTo(a).iterator();
      while (refs.hasNext()) {
        Reference r = refs.next();
        if (!r.getReferenceType().isCall()) continue;
        Instruction call = getInstructionAt(r.getFromAddress());
        if (call == null) continue;
        // A `bl` only: a tail-branching `b` to a restore helper is a call that returns by design.
        FlowType original = call.getPrototype().getFlowType(call.getInstructionContext());
        if (!original.isCall() || !original.hasFallthrough()) continue;
        boolean changed = false;
        if (call.getFlowOverride() == FlowOverride.CALL_RETURN) {
          call.setFlowOverride(FlowOverride.NONE);
          changed = true;
        }
        Address next = call.getMaxAddress().add(1);
        if (getInstructionAt(next) == null && getDataAt(next) == null) {
          disassemble(next);
          changed = true;
        }
        if (changed) calls++;
        Function caller = getFunctionContaining(call.getAddress());
        if (changed && caller != null) callers.add(caller.getEntryPoint());
      }
    }
    for (Address entry : callers) {
      Function f = getFunctionAt(entry);
      if (f != null) CreateFunctionCmd.fixupFunctionBody(currentProgram, f, monitor);
    }
    return new int[] {calls, callers.size()};
  }

  // The PE loader does not read a PowerPC .pdata (8-byte entries, begin address first, big-endian);
  // XEXLoaderWV does. Defines the functions it lists where none exists yet.
  int pdata() throws Exception {
    MemoryBlock block = mem.getBlock(".pdata");
    if (block == null || !block.isInitialized()) return 0;
    int created = 0;
    Address end = block.getEnd().subtract(7);
    for (Address a = block.getStart(); a.compareTo(end) <= 0; a = a.add(8)) {
      monitor.checkCancelled();
      long begin = word(a) & 0xFFFFFFFFL;
      if (begin == 0) continue;
      Address entry = toAddr(begin);
      MemoryBlock target = mem.getBlock(entry);
      if (target == null || !target.isExecute() || getFunctionAt(entry) != null) continue;
      if (getInstructionAt(entry) == null) disassemble(entry);
      if (new CreateFunctionCmd(entry).applyTo(currentProgram, monitor)) created++;
    }
    return created;
  }

  static String opcodeJson(TreeMap<Integer, Integer> opcodes) {
    List<String> parts = new ArrayList<>();
    opcodes.forEach((op, n) -> parts.add("\"" + op + "\": " + n));
    return String.join(", ", parts);
  }

  @Override
  public void run() throws Exception {
    String[] args = getScriptArgs();
    if (args.length != 2 || !(args[0].equals("prepare") || args[0].equals("repair"))) {
      throw new IllegalArgumentException("usage: XenonHelpers.java prepare|repair <summary.json>");
    }
    mem = currentProgram.getMemory();
    int fromPdata = args[0].equals("prepare") ? pdata() : 0;
    find();
    if (!helpers.isEmpty()
        && SpecExtension.getCompilerSpecExtension(
                currentProgram, SpecExtension.Type.CALL_FIXUP, FIXUP) == null) {
      new SpecExtension(currentProgram).addReplaceCompilerSpecExtension(FIXUP_XML, monitor);
    }
    int created = mark();
    int[] repaired = {0, 0};
    if (args[0].equals("repair")) {
      repaired = repair();
    }

    List<String> undecoded = new ArrayList<>();
    Iterator<Bookmark> marks =
        currentProgram.getBookmarkManager().getBookmarksIterator(BookmarkType.ERROR);
    int bad = 0;
    TreeMap<Integer, Integer> opcodes = new TreeMap<>(); // primary opcode -> count
    while (marks.hasNext()) {
      Bookmark b = marks.next();
      if (!b.getCategory().equals("Bad Instruction")) continue;
      if (undecoded.size() < 20) undecoded.add("\"" + b.getAddress() + "\"");
      try {
        opcodes.merge(word(b.getAddress()) >>> 26, 1, Integer::sum);
      } catch (MemoryAccessException e) {
        opcodes.merge(-1, 1, Integer::sum);
      }
      bad++;
    }
    try (PrintWriter out = new PrintWriter(args[1], "UTF-8")) {
      out.printf(
          "{\"mode\": \"%s\", \"language\": \"%s\", \"helpers\": %d,"
              + " \"helpers_created\": %d, \"pdata_functions\": %d,"
              + " \"first_helper\": %s, \"calls_repaired\": %d, \"callers_repaired\": %d,"
              + " \"undecoded_instructions\": %d, \"undecoded_sample\": [%s],"
              + " \"undecoded_opcodes\": {%s}}%n",
          args[0], currentProgram.getLanguageID(), helpers.size(), created, fromPdata,
          helpers.isEmpty() ? "null" : "\"" + helpers.firstKey() + "\"", repaired[0], repaired[1],
          bad, String.join(", ", undecoded), opcodeJson(opcodes));
    }
    println("XenonHelpers " + args[0] + ": " + helpers.size() + " helper entries, " + repaired[0]
        + " calls repaired, " + bad + " undecoded instructions");
  }
}
