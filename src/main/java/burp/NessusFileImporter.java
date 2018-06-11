package burp;

import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.Node;
import org.w3c.dom.NodeList;

import javax.xml.parsers.DocumentBuilder;
import java.io.File;
import java.net.MalformedURLException;
import java.net.URI;
import java.net.URISyntaxException;
import java.net.URL;
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
        //  There may be a Location field in the plugin output headers, which gives us a lot.
        //  If there's "SSL : yes" in the plugin output, we have an https
        //  If there's "SSL : no" in the plugin output, we have http
        //  If it doesn't, check the port against defaults (eg 80 for http, 443 for https)

        NodeList reportHosts= doc.getElementsByTagName("ReportHost");

        int numHosts = reportHosts.getLength();
        for (int hostIndex = 0; hostIndex < numHosts; hostIndex++){
            Node reportHost = reportHosts.item(hostIndex);
            sites.addAll(getSitesFromHost(reportHost));
        }

        return sites;
    }

    private List<String> getSitesFromHost(Node reportHost) {

        List<String> sites = new ArrayList<>();

        String hostIP = reportHost.getAttributes().getNamedItem("name").getNodeValue();
        NodeList reportItems = ((Element) reportHost).getElementsByTagName("ReportItem");

        for (int reportItemIndex = 0; reportItemIndex < reportItems.getLength(); reportItemIndex++) {
            Node reportItem = reportItems.item(reportItemIndex);

            if (!reportItem.getAttributes().getNamedItem("pluginID").getNodeValue().equals(NESSUS_HTTP_INFO_PLUGIN_ID)) {
                continue;
            }

            String pluginOutput = ((Element) reportItem).getElementsByTagName("plugin_output").item(0).getTextContent();
            String locationHeader = retrieveLocationHeader(pluginOutput);

            int port = Integer.parseInt(reportItem.getAttributes().getNamedItem("port").getNodeValue());

            if (locationHeader.length() == 0){
                String url = createUrlFromHostAndPort(hostIP, port, reportItem, pluginOutput);
                sites.add(url);
            } else if (locationHeaderIsAbsolute(locationHeader)){
                sites.add(locationHeader);
            } else {
                String url = createUrlFromRelativeLocationHeader (hostIP, port, locationHeader, pluginOutput );
                sites.add(url);
            }
        }

        return sites;

    }

    private String createUrlFromRelativeLocationHeader(String hostIP, int port, String locationHeader, String pluginOutput) {
        String scheme = calculateSchemeFromPortAndPlugin(port, pluginOutput);

        URL url;

        if (!locationHeader.startsWith("/")){
            locationHeader = "/" + locationHeader;
        }

        try {
            url = new URL(scheme, hostIP, port, locationHeader);
        } catch (MalformedURLException e) {
            return "";
        }

        return url.toString();
    }

    private boolean locationHeaderIsAbsolute(String locationHeader){
        URI headerUri = null;
        try {
            headerUri = new URI(locationHeader);
        } catch (URISyntaxException e) {
            return false;
        }
        return headerUri.isAbsolute();
    }

    private String retrieveLocationHeader(String pluginContents){
        Pattern regex = Pattern.compile("Location: (.+)\n");
        Matcher regexMatcher = regex.matcher(pluginContents);
        if (regexMatcher.find() && regexMatcher.groupCount() == 1){
            return regexMatcher.group(1);
        }

        return "";
    }

    private String createUrlFromHostAndPort(String hostIP, int port, Node reportItem, String pluginOutput) {

        String scheme = calculateSchemeFromPortAndPlugin(port, pluginOutput);
        return String.format("%s://%s:%d", scheme, hostIP, port);
    }

    private String calculateSchemeFromPortAndPlugin(int port, String pluginOutput){
        if (pluginOutput.contains("SSL : yes")){
            return "https";
        } else if (pluginOutput.contains("SSL : no")) {
            return "http";
        }

        return isAnHttpsPort(port)?"https":"http";
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
