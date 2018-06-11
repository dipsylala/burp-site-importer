import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.Node;
import org.w3c.dom.NodeList;

import javax.xml.parsers.DocumentBuilder;
import javax.xml.xpath.*;
import java.io.File;
import java.util.ArrayList;
import java.util.List;

public class NmapFileImporter extends XmlImporterBase implements ISiteImporter {

    private IListScannerLogger logger;

    public NmapFileImporter(IListScannerLogger logger){

        this.logger = logger;
    }

    public List<String> loadFile(File file) {

        List<String> sites = new ArrayList<>();
        DocumentBuilder safeDocBuilder = createSafeDocumentFactory();
        if (safeDocBuilder == null){
            this.logger.log("Could not create safe XML document handler");
            return sites;
        }

        Document doc = loadFileIntoDocument(safeDocBuilder, file);

        // Quicker to use XPATH to return the hosts that only contain
        // what we're interested in, due to the hierarchical nature of
        // the nmap XML
        NodeList hostNodes = getHttpHostsFromXmlDocument(doc);
        if (hostNodes == null) {
            return sites;
        }

        for (int i = 0; i < hostNodes.getLength(); i++) {

            NodeList serviceNodes = ((Element) hostNodes.item(i)).getElementsByTagName("service");
            NodeList hostNameNodes = ((Element) hostNodes.item(i)).getElementsByTagName("hostname");
            for (int j = 0; j < serviceNodes.getLength(); j++) {
                Node serviceNode = serviceNodes.item(j);

                boolean isHttps = isServiceNodeHttps(serviceNode);

                int port = getPortFromServiceNode(serviceNode);
                String hostName = hostNameNodes.item(0).getAttributes().getNamedItem("name").getNodeValue();

                String url = (isHttps?"https":"http") + "://" + hostName + ":" + port;
                sites.add(url);
            }
        }

        return sites;
    }

    @Override
    public boolean canParseFile(File file) {

        // nmap XML files have a single root node of 'nmaprun'
        DocumentBuilder safeDocBuilder = createSafeDocumentFactory();
        if (safeDocBuilder == null){
            return false;
        }

        Document doc = loadFileIntoDocument(safeDocBuilder, file);
        if (doc == null){
            return false;
        }

        NodeList nmapFound = doc.getElementsByTagName("nmaprun");
        return nmapFound.getLength()==1;
    }

    private int getPortFromServiceNode(Node serviceNode) {
        return Integer.parseInt(serviceNode.getParentNode().getAttributes().getNamedItem("portid").getNodeValue());
    }

    private boolean isServiceNodeHttps(Node serviceNode) {
        boolean isHttps = false;

        Node nameNode = serviceNode.getAttributes().getNamedItem("name");
        Node tunnelNode = serviceNode.getAttributes().getNamedItem("tunnel");

        if (nameNode.getNodeValue().equals("https")){
            isHttps = true;
        } else {
            if (tunnelNode!=null){
                isHttps = true;
            }
        }

        return isHttps;
    }

    private NodeList getHttpHostsFromXmlDocument(Document doc) {
        XPathFactory xPathfactory = XPathFactory.newInstance();
        XPath xpath = xPathfactory.newXPath();

        // depending on the kind of scan, service name might be https, or http with an optional tunnel
        // regardless of what we find, quicker to find get each host and work down from there.
        XPathExpression expr = null;
        try {
            expr = xpath.compile("//service[@name='http' or @name='https']/ancestor::host");
            return (NodeList) expr.evaluate(doc, XPathConstants.NODESET);
        } catch (XPathExpressionException e) {
            return null;
        }
    }


}
