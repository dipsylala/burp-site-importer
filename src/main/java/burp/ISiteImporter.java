package burp;

import java.io.File;
import java.util.List;

public interface ISiteImporter {
    List<String> loadFile(File file);
    boolean canParseFile (File file);
}
