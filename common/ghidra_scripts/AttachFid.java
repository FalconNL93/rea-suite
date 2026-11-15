// Attaches a FunctionID database for this run's analysis only: as a pre-script `attach`, as the
// matching post-script `detach`, so it is not left in Ghidra's settings for every later analysis.
// Usage: -preScript AttachFid.java attach <db.fidb> ... -postScript AttachFid.java detach <db.fidb>
import ghidra.app.script.GhidraScript;
import ghidra.feature.fid.db.FidFile;
import ghidra.feature.fid.db.FidFileManager;
import java.io.File;

public class AttachFid extends GhidraScript {
  @Override
  public void run() throws Exception {
    String[] a = getScriptArgs();
    FidFileManager files = FidFileManager.getInstance();
    File db = new File(a[1]);
    if (a[0].equals("attach")) {
      FidFile f = files.addUserFidFile(db);
      if (f != null) {
        f.setActive(true);
      }
      println("AttachFid: attached " + db + (f == null ? " (failed)" : ""));
      return;
    }
    for (FidFile f : files.getUserAddedFiles()) {
      if (new File(f.getPath()).getCanonicalFile().equals(db.getCanonicalFile())) {
        files.removeUserFile(f);
        println("AttachFid: detached " + db);
      }
    }
  }
}
