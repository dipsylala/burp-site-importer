import org.w3c.dom.Document;
import org.w3c.dom.Node;
import org.w3c.dom.NodeList;

import javax.xml.parsers.DocumentBuilder;
import javax.xml.xpath.*;
import java.io.File;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

public class OpenVasFileImporter extends XmlImporterBase implements ISiteImporter{

    private IListScannerLogger logger;
    private List<Integer> httpPorts = Arrays.asList(80,81,82,83,2301,8000,8008,8080,8180,8400,8888,9001,9080,9090,9100);
    private List<Integer> httpsPorts = Arrays.asList(443, 2381, 8083, 8443, 8834, 9043, 9443);

    public OpenVasFileImporter(IListScannerLogger logger){

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

        NodeList vasResultNodes = getResultsFromXmlDocument(doc);

        if (vasResultNodes == null) {
            return sites;
        }

        for (int i = 0; i< vasResultNodes.getLength(); i++){
            Node vasResultNode = vasResultNodes.item(i);

            SiteInformation siteInfo = getSiteInfoFromResult (vasResultNode);

            if (siteInfo == null){
                continue;
            }

            String url = getUrlFromSiteInfo (siteInfo);

            if (url.length()!= 0){
                sites.add(url);
            }
        }

        return sites;
    }

    private String getUrlFromSiteInfo(SiteInformation siteInfo) {
        if (!siteInfo.protocol.equals("tcp") || siteInfo.port == 0){
            return "";
        }

        String scheme;
        if (isAnHttpPort(siteInfo.port)){
            scheme = "http://";
        } else if (isAnHttpsPort(siteInfo.port)) {
            scheme = "https://";
        } else {
            return "";
        }

        return String.format("%s%s:%d", scheme, siteInfo.host, siteInfo.port);
    }

    private SiteInformation getSiteInfoFromResult(Node vasResultNode) {
        Node portNode = getChildNodeByName(vasResultNode,"port");
        Node hostNode = getChildNodeByName(vasResultNode, "host");

        if (portNode == null || hostNode == null){
            return null;
        }

        SiteInformation siteInformation = new SiteInformation();
        siteInformation.host = hostNode.getFirstChild().getTextContent().trim();

        String portAndProtocol = portNode.getFirstChild().getTextContent();

        // Thanks to https://bitbucket.org/memoryresident/goxparse for the logic here.
        // cases where port looks like "general/ICMP"
        if (portAndProtocol.startsWith("general/")){
            String []splitString = portAndProtocol.split("/");
            siteInformation.service = splitString[0];
            siteInformation.protocol = splitString[1];
            siteInformation.port = 0;
        } else if (portAndProtocol.contains("(")) { // cases where port looks like "ntp(123/udp)"
            String [] splitString = portAndProtocol.replace(")","").replace(" (","/").split("/");
            siteInformation.service = splitString[0];
            siteInformation.protocol = splitString[2];
            siteInformation.port = Integer.parseInt(splitString[1]);
        } else { // otherwise: port looks like "123/udp"
            String [] splitString =  portAndProtocol.split("/");

            siteInformation.service = ""; // empty for now so will leave it blank
            siteInformation.protocol = splitString[1];
            siteInformation.port = Integer.parseInt(splitString[0]);
        }

        return siteInformation;
    }

    @Override
    public boolean canParseFile(File file) {
        // OpenVAS XML files have a node of 'omp'
        DocumentBuilder safeDocBuilder = createSafeDocumentFactory();
        if (safeDocBuilder == null){
            return false;
        }

        Document doc = loadFileIntoDocument(safeDocBuilder, file);
        if (doc == null){
            return false;
        }

        NodeList openVasFound = doc.getElementsByTagName("omp");
        return openVasFound.getLength()==1;
    }

    private boolean isAnHttpPort (int port){
        return httpPorts.contains(port);
    }

    private boolean isAnHttpsPort (int port){
        return httpsPorts.contains(port);
    }

    private NodeList getResultsFromXmlDocument(Document doc) {
        XPathFactory xPathfactory = XPathFactory.newInstance();
        XPath xpath = xPathfactory.newXPath();

        // depending on the kind of scan, service name might be https, or http with an optional tunnel
        // regardless of what we find, quicker to find get each host and work down from there.
        try {
            XPathExpression expr = xpath.compile("//report/results/result");
            return (NodeList) expr.evaluate(doc, XPathConstants.NODESET);
        } catch (XPathExpressionException e) {
            return null;
        }
    }

    private Node getChildNodeByName(Node node, String name){

        NodeList childNodes = node.getChildNodes();

        for (int i = 0; i< node.getChildNodes().getLength(); i++){
            if (childNodes.item(i).getNodeName().equals(name)){
                return childNodes.item(i);
            }
        }

        return null;
    }
}
