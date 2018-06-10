package burp;

import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.Node;
import org.w3c.dom.NodeList;

import javax.xml.parsers.DocumentBuilder;
import javax.xml.xpath.*;
import java.io.File;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

public class NessusFileImporter extends XmlImporterBase implements ISiteImporter{

    private IListScannerLogger logger;
    private List<Integer> httpPorts = Arrays.asList(80,81,82,83,2301,8000,8008,8080,8180,8400,8888,9001,9080,9090,9100);
    private List<Integer> httpsPorts = Arrays.asList(443, 2381, 8083, 8443, 8834, 9043, 9443);

    private static final String NESSUS_HTTP_INFO_PLUGIN_ID = "24260";

    public NessusFileImporter(IListScannerLogger logger){

        this.logger = logger;
    }

    @Override
    public List<String> loadFile(File file) {
        List<String> sites = new ArrayList<>();
        DocumentBuilder safeDocBuilder = createSafeDocumentFactory();
        if (safeDocBuilder == null){
            this.logger.log("Could not create safe XML document handler");
            return sites;
        }

        Document doc = loadFileIntoDocument(safeDocBuilder, file);

        // Each host gets a ReportHost.
        // under each one, Nessus drops its results in a get of ReportItem elements.
        // Each ReportItem is the result of a plugin
        // Plugin ID 22964 is the Service Detection
        // Plugin ID 24260 is 'HTTP Information' and does a lot of the work for us
        // We can derive the URL:
        //  There may be a Location field in the plugin output, which gives us a lot.
        //  If it has "SSL : yes" in the plugin output, we have an https
        //  If it has "SSL : no" in the plugin output, we have http
        //  If it doesn't, check the port against defaults (eg 80 for http, 443 for https)



        NodeList reportHosts= doc.getElementsByTagName("ReportHost");

        Pattern locationPattern = Pattern.compile("Location: (.+?)\\n");

        int numHosts = reportHosts.getLength();
        for (int i = 0; i< numHosts; i++){
            Node reportHost = reportHosts.item(i);

            String hostIP = reportHost.getAttributes().getNamedItem("name").getNodeValue();
            NodeList reportItems = ((Element) reportHost).getElementsByTagName("ReportItem");

            for (int j = 0; j < reportItems.getLength(); j++){
                Node reportItem = reportItems.item(j);

                if (!reportItem.getAttributes().getNamedItem("pluginID").getNodeValue().equals(NESSUS_HTTP_INFO_PLUGIN_ID)){
                    continue;
                }

                String port = reportItem.getAttributes().getNamedItem("port").getNodeValue();
                String pluginOutput = ((Element)reportItem).getElementsByTagName("plugin_output").item(0).getTextContent();

                Matcher m = locationPattern.matcher(pluginOutput);
            }

        }

        return sites;
    }

    @Override
    public boolean canParseFile(File file) {
        // Nessus v2 files have a node of 'NessusClientData_v2'
        DocumentBuilder safeDocBuilder = createSafeDocumentFactory();
        if (safeDocBuilder == null){
            return false;
        }

        Document doc = loadFileIntoDocument(safeDocBuilder, file);
        if (doc == null){
            return false;
        }

        NodeList nmapFound = doc.getElementsByTagName("NessusClientData_v2");
        return nmapFound.getLength()==1;
    }

    private boolean isAnHttpPort (int port){
        return httpPorts.contains(port);
    }

    private boolean isAnHttpsPort (int port){
        return httpsPorts.contains(port);
    }
}
