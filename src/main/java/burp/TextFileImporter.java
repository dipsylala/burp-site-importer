package burp;

import java.io.*;
import java.util.ArrayList;
import java.util.List;

public class TextFileImporter implements ISiteImporter{

    private IListScannerLogger logger;

    TextFileImporter (IListScannerLogger logger){

        this.logger = logger;
    }

    public List<String> loadFile(File file) {

        List<String> sites = new ArrayList<>();

        int lineCount = 0;

        try(BufferedReader br = new BufferedReader(new FileReader(file.getAbsoluteFile()))) {
            String line = br.readLine();

            while (line != null) {
                line = line.trim();
                if (line.length() > 0) {
                    lineCount++;

                    sites.add(line);
                }

                line = br.readLine();
            }


        } catch (FileNotFoundException e) {
            this.logger.log("File not found: " + file.getName());
        } catch (IOException e) {
            this.logger.log("Error reading file: " + file.getName());
        }


        return sites;
    }

    @Override
    public boolean canParseFile(File file) {
        return (getExtension(file).toLowerCase().equals("txt"));
    }

    String getExtension(File file){
        String fileName = file.getName();

        if(fileName.lastIndexOf(".") != -1 && fileName.lastIndexOf(".") != 0)
            return fileName.substring(fileName.lastIndexOf(".")+1);

        return "";
    }
}
