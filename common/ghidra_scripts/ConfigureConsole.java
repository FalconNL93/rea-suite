// Disable Kaiju hashing on PSX/R5900, where its instruction categorizer throws errors.
// Usage (headless pre-script): ConfigureConsole.java
import ghidra.app.script.GhidraScript;
import ghidra.program.model.listing.Program;

public class ConfigureConsole extends GhidraScript {
  @Override
  public void run() throws Exception {
    currentProgram.getOptions(Program.ANALYSIS_PROPERTIES)
        .setBoolean("CERT Kaiju Function Hashing", false);
    println("Disabled CERT Kaiju Function Hashing for console analysis");
  }
}
