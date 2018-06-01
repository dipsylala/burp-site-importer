package burp;

import java.net.MalformedURLException;
import java.net.URI;
import java.net.URISyntaxException;
import java.net.URL;
import java.util.ArrayList;
import java.util.List;

public class SiteCallRunnable implements Runnable {

    private IExtensionHelpers helpers;
    private IBurpExtenderCallbacks callbacks;
    private ISiteImportSummary summary;
    private String site;
    private final boolean addToScope;
    private boolean deepScan;
    private boolean followRedirects;
    private IListScannerLogger logger;

    SiteCallRunnable(IExtensionHelpers helpers,
                     IBurpExtenderCallbacks callbacks,
                     IListScannerLogger logger,
                     ISiteImportSummary summary,
                     String site,
                     SiteImportSettings settings) {
        this.helpers = helpers;
        this.callbacks = callbacks;
        this.summary = summary;
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
            summary.addBadURL(site);
            logger.log(site + " is not a valid url");
            return;
        }

        if (isSiteAlreadyVisited(site, redirectedSites)){
            return;
        }

        logger.log("Checking: " + site);

        IHttpRequestResponse siteRequestResponse;

        try{
            siteRequestResponse = makeRequestToSite(url);
            callbacks.addToSiteMap(siteRequestResponse);
        } catch (RuntimeException ex){
            summary.addUnreachableSite(site);
            return;
        }

        IResponseInfo responseInfo = getResponseInfoFromRequestResponse(siteRequestResponse);

        if (this.addToScope){
            callbacks.includeInScope(url);
        }

        if (this.deepScan){
            callbacks.sendToSpider(url);
        }

        if (this.followRedirects && isARedirect(responseInfo)){
            String redirectSite = getRedirectLocation(responseInfo);

            logger.log("Redirection found: " + redirectSite);

            String resolveRedirectSite = getRedirectionSite(site, redirectSite);

            if (resolveRedirectSite.length()>0){
                assessSite(resolveRedirectSite, redirectedSites);
            }
        }
    }

    private IResponseInfo getResponseInfoFromRequestResponse(IHttpRequestResponse siteRequestResponse) {
        byte[] responseBytes = siteRequestResponse.getResponse();
        return helpers.analyzeResponse(responseBytes);
    }

    private String getRedirectionSite(String originalSite, String redirectHeaderValue) {

        URI redirectSiteUri;

        try {
            redirectSiteUri = new URI(redirectHeaderValue);
        } catch (URISyntaxException e) {
            return "";
        }

        if (redirectSiteUri.isAbsolute()) {
            return redirectHeaderValue;
        }

        URI siteUri = URI.create(originalSite);
        siteUri = siteUri.resolve(redirectHeaderValue);
        return siteUri.toString();
    }

    private IHttpRequestResponse makeRequestToSite(URL url) {
        int port = url.getPort();
        if (port == -1 ){
            port = url.getDefaultPort();
        }

        IHttpService httpService = helpers.buildHttpService(url.getHost(), port, url.getProtocol());
        byte[] httpRequest = helpers.buildHttpRequest(url);
        return callbacks.makeHttpRequest(httpService, httpRequest);
    }

    private boolean isSiteAlreadyVisited(String site, List<String> redirectedSites) {
        if (redirectedSites.contains(site)){
            return true;
        }

        redirectedSites.add(site);
        return false;
    }

    private boolean isARedirect(IResponseInfo response){
        int statusCode = response.getStatusCode();

        return statusCode >= 300 && statusCode < 400;
    }
    
    private String getRedirectLocation(IResponseInfo responseInfo){
        List<String>headers = responseInfo.getHeaders();
        for (String header : headers){
            if (header.toLowerCase().startsWith("location:")){
                return header.substring(10).trim();
            }
        }

        return "";
    }
}
