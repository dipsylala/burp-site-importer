package burp;

import java.io.File;

public abstract class FileImporterBase {
    protected String getExtension(File file){
        String fileName = file.getName();

        if(fileName.lastIndexOf(".") != -1 && fileName.lastIndexOf(".") != 0)
            return fileName.substring(fileName.lastIndexOf(".")+1);

        return "";
    }
}
