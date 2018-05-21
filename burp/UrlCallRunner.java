package burp;

import java.net.MalformedURLException;
import java.net.URL;
import java.util.List;

public class UrlCallRunner implements Runnable {

    private IExtensionHelpers helpers;
    private IBurpExtenderCallbacks callbacks;
    private final List<String> sites;
    private final boolean addToScope;
    private boolean deepScan;

    UrlCallRunner(IExtensionHelpers helpers, IBurpExtenderCallbacks callbacks, List<String> sites, boolean addToScope, boolean deepScan) {

        this.helpers = helpers;
        this.callbacks = callbacks;
        this.sites = sites;
        this.addToScope = addToScope;
        this.deepScan = deepScan;
    }

    @Override
    public void run() {
        try {

            for (String site : sites){

                URL url = new URL(site);

                int port = url.getPort();
                if (port ==  -1){
                    port = url.getDefaultPort();
                }

                IHttpService httpService = helpers.buildHttpService(url.getHost(), port, url.getProtocol());
                byte[] httpRequest = helpers.buildHttpRequest(url);
                callbacks.addToSiteMap(callbacks.makeHttpRequest(httpService, httpRequest));

                if (this.addToScope){
                    callbacks.includeInScope(url);
                }

                if (this.deepScan){
                    callbacks.sendToSpider(url);
                }

            }

        } catch (MalformedURLException e) {
            e.printStackTrace();
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}
