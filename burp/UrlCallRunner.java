package burp;

import java.net.MalformedURLException;
import java.net.URL;
import java.util.ArrayList;
import java.util.List;

public class UrlCallRunner implements Runnable {

    private IExtensionHelpers helpers;
    private IBurpExtenderCallbacks callbacks;
    private String site;
    private final boolean addToScope;
    private boolean deepScan;
    private boolean followRedirects;
    private IListScannerLogger logger;

    UrlCallRunner(IExtensionHelpers helpers, IBurpExtenderCallbacks callbacks, IListScannerLogger logger, String site, SiteImportSettings settings) {
        this.helpers = helpers;
        this.callbacks = callbacks;
        this.site = site;
        this.addToScope = settings.addToScope;
        this.deepScan = settings.deepScan;
        this.followRedirects = settings.followRedirects;
        this.logger = logger;
    }

    @Override
    public void run() {
        List<String> redirectionList = new ArrayList<>();
        assessSite(site, redirectionList);
    }

    private void assessSite(String site, List<String> redirectedSites){

        URL url;
        try {
            url = new URL(site);
        } catch (MalformedURLException e) {
            return;
        }

        if (siteAlreadyVisited(site, redirectedSites)){
            return;
        }

        logger.Log("Checking: " + site + System.lineSeparator());
        IHttpRequestResponse httpResponse = connectToSite(url);
        callbacks.addToSiteMap(httpResponse);

        if (this.addToScope){
            callbacks.includeInScope(url);
        }

        if (this.deepScan){
            callbacks.sendToSpider(url);
        }

        if (this.followRedirects){

            String redirectSite = getRedirect (httpResponse.getResponse());

            if (redirectSite.length() > 0){
                logger.Log("Redirection found: " + redirectSite + System.lineSeparator());
                assessSite(redirectSite, redirectedSites);
            }
        }
    }

    private IHttpRequestResponse connectToSite(URL url) {
        int port = url.getPort();
        if (port == -1 ){
            port = url.getDefaultPort();
        }

        IHttpService httpService = helpers.buildHttpService(url.getHost(), port, url.getProtocol());
        byte[] httpRequest = helpers.buildHttpRequest(url);
        return callbacks.makeHttpRequest(httpService, httpRequest);
    }

    private boolean siteAlreadyVisited(String site, List<String> redirectedSites) {
        if (redirectedSites.contains(site)){
            return true;
        }

        redirectedSites.add(site);
        return false;
    }

    private String getRedirect(byte[] responseBytes){
        IResponseInfo response = helpers.analyzeResponse(responseBytes);

        int statusCode = response.getStatusCode();

        if (statusCode < 300 || statusCode >= 400 ){
            return "";
        }

        List<String>headers = response.getHeaders();
        for (String header : headers){
            if (header.startsWith("Location:")){
                return header.substring(10).trim();
            }
        }

        return "";
    }
}
