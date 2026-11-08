// Applies a port's names and comments to the program: each line of <in.tsv> is "address<TAB>name<TAB>comment"
// (comment may be empty). A function or label named by Ghidra (FUN_..., a default or analysis name) takes the
// name; one a person or an import named keeps its own and is reported "kept", as is a different plate comment.
// Writes one line per entry to <out.tsv>: address, what happened (named, same, kept, invalid, missing), the old
// name, the new one.
// Usage (headless post-script, without -readOnly): ApplyNames.java <in.tsv> <out.tsv>
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;
import ghidra.program.model.symbol.SourceType;
import ghidra.program.model.symbol.Symbol;
import java.io.PrintWriter;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;

public class ApplyNames extends GhidraScript {
  @Override
  public void run() throws Exception {
    String[] args = getScriptArgs();
    try (PrintWriter out = new PrintWriter(args[1], "UTF-8")) {
      out.println("address\tresult\told\tnew");
      for (String line : Files.readAllLines(Path.of(args[0]), StandardCharsets.UTF_8)) {
        if (line.isBlank()) {
          continue;
        }
        String[] f = line.split("\t", -1);
        String address = f[0], name = f.length > 1 ? f[1] : "", comment = f.length > 2 ? f[2] : "";
        out.println(address + "\t" + apply(address, name.trim(), comment.trim()));
      }
    }
  }

  private String apply(String text, String name, String comment) {
    Address a;
    try {
      a = currentProgram.getAddressFactory().getAddress(text);
    } catch (Exception e) {
      a = null;
    }
    if (a == null || !currentProgram.getMemory().contains(a)) {
      return "missing\t\t" + name;
    }
    Function fn = getFunctionAt(a);
    Symbol symbol = fn != null ? fn.getSymbol() : getSymbolAt(a);
    String old = symbol != null ? symbol.getName() : "";
    String result;
    try {
      if (old.equals(name)) {
        result = "same";
      } else if (symbol != null && (symbol.getSource() == SourceType.USER_DEFINED
          || symbol.getSource() == SourceType.IMPORTED)) {
        result = "kept";
      } else if (fn != null) {
        fn.setName(name, SourceType.USER_DEFINED);
        result = "named";
      } else {
        createLabel(a, name, true, SourceType.USER_DEFINED);
        result = "named";
      }
    } catch (Exception e) {
      return "invalid\t" + old + "\t" + name;
    }
    if (!comment.isEmpty()) {
      String plate = getPlateComment(a);
      if (plate == null || plate.isBlank()) {
        setPlateComment(a, comment);
      } else if (!plate.equals(comment) && result.equals("same")) {
        result = "kept";
      }
    }
    return result + "\t" + old + "\t" + name;
  }
}
