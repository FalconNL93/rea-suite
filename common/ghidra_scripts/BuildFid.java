// Builds (or extends) a FunctionID database from every analyzed program under a project folder, as
// Ghidra's CreateMultipleLibraries.java does, but from arguments instead of dialogs (headless).
// Usage (headless pre-script, no program): BuildFid.java <out.fidb> <project folder> <family>
//   <version> <variant> <language id> [common symbols file]
import ghidra.app.script.GhidraScript;
import ghidra.feature.fid.db.FidDB;
import ghidra.feature.fid.db.FidFile;
import ghidra.feature.fid.db.FidFileManager;
import ghidra.feature.fid.service.FidPopulateResult;
import ghidra.feature.fid.service.FidService;
import ghidra.framework.model.DomainFile;
import ghidra.framework.model.DomainFolder;
import ghidra.program.database.ProgramContentHandler;
import ghidra.program.model.lang.LanguageID;
import java.io.File;
import java.nio.file.Files;
import java.util.ArrayList;
import java.util.List;

public class BuildFid extends GhidraScript {
  @Override
  public void run() throws Exception {
    String[] a = getScriptArgs();
    File out = new File(a[0]);
    DomainFolder folder = state.getProject().getProjectData().getFolder(a[1]);
    if (folder == null) {
      throw new IllegalArgumentException("no project folder " + a[1]);
    }
    List<String> common = null;
    if (a.length > 6) {
      common = new ArrayList<>();
      for (String line : Files.readAllLines(new File(a[6]).toPath())) {
        if (!line.isBlank()) {
          common.add(line.trim());
        }
      }
    }
    FidFileManager files = FidFileManager.getInstance();
    if (!out.exists()) {
      files.createNewFidDatabase(out);
    }
    FidFile fidFile = files.addUserFidFile(out);
    List<DomainFile> programs = new ArrayList<>();
    collect(folder, programs);
    FidDB db = fidFile.getFidDB(true);
    try {
      FidPopulateResult result = new FidService().createNewLibraryFromPrograms(db, a[2], a[3], a[4],
          programs, null, new LanguageID(a[5]), null, common, monitor);
      println("BuildFid: " + programs.size() + " programs, " + result.getTotalAttempted()
          + " functions visited, " + result.getTotalAdded() + " added, " + result.getTotalExcluded()
          + " excluded");
      db.saveDatabase("Saving", monitor);
    } finally {
      db.close();
      files.removeUserFile(fidFile); // not left attached to every later analysis (AttachFid.java)
    }
  }

  private void collect(DomainFolder folder, List<DomainFile> programs) throws Exception {
    for (DomainFile f : folder.getFiles()) {
      monitor.checkCancelled();
      if (f.getContentType().equals(ProgramContentHandler.PROGRAM_CONTENT_TYPE)) {
        programs.add(f);
      }
    }
    for (DomainFolder sub : folder.getFolders()) {
      collect(sub, programs);
    }
  }
}
