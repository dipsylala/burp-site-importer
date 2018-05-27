package burp;


import java.util.List;
import java.util.concurrent.Executors;
import java.util.concurrent.ThreadPoolExecutor;

public class UrlCallThreadManager  implements Runnable {

    private IExtensionHelpers helpers;
    private IBurpExtenderCallbacks callbacks;
    SiteImportSettings settings;
    private IListScannerLogger logger;
    List<String> sites;


    UrlCallThreadManager(IExtensionHelpers helpers, IBurpExtenderCallbacks callbacks, IListScannerLogger logger, List<String> sites, SiteImportSettings settings) {
        this.logger = logger;
        this.sites = sites;
        this.helpers = helpers;
        this.callbacks = callbacks;
        this.settings = settings;
    }

    @Override
    public void run() {

        ThreadPoolExecutor executor = (ThreadPoolExecutor) Executors.newFixedThreadPool(10);

        for (String site : sites) {
            UrlCallRunner urlCall = new UrlCallRunner(this.helpers, this.callbacks, this.logger, site, this.settings);
            executor.execute(urlCall);
        }

        executor.shutdown();
    }
}
