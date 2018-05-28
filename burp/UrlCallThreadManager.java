package burp;


import java.util.List;
import java.util.concurrent.Executors;
import java.util.concurrent.ThreadPoolExecutor;

public class UrlCallThreadManager  implements Runnable {

    private IExtensionHelpers helpers;
    private IBurpExtenderCallbacks callbacks;
    private SiteImportSettings settings;
    private IListScannerLogger logger;
    private List<String> sites;
    private boolean completedTask = false;


    UrlCallThreadManager(IExtensionHelpers helpers, IBurpExtenderCallbacks callbacks, IListScannerLogger logger, List<String> sites, SiteImportSettings settings) {
        this.logger = logger;
        this.sites = sites;
        this.helpers = helpers;
        this.callbacks = callbacks;
        this.settings = settings;
    }

    public boolean getCompleted(){
        return this.completedTask;
    }

    @Override
    public void run() {

        ThreadPoolExecutor executor = (ThreadPoolExecutor) Executors.newFixedThreadPool(10);

        for (String site : this.sites) {
            UrlCallRunner urlCall = new UrlCallRunner(this.helpers, this.callbacks, this.logger, site, this.settings);
            executor.execute(urlCall);
        }

        executor.shutdown();
        while (!executor.isTerminated()) {
            try {
                Thread.sleep(100);
            } catch (InterruptedException e) {
                e.printStackTrace();
            }
        }

        this.logger.Log("All Threads Processed");
        this.completedTask = true;

    }
}