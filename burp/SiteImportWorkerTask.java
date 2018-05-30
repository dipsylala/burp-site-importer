package burp;

import javax.swing.*;
import java.util.List;
import java.util.concurrent.Executors;
import java.util.concurrent.ThreadPoolExecutor;
import java.util.concurrent.TimeUnit;

public class SiteImportWorkerTask extends SwingWorker<Void, Void> {

    private IExtensionHelpers helpers;
    private IBurpExtenderCallbacks callbacks;
    private SiteImportSettings settings;
    private IListScannerLogger logger;
    private ISiteImportSummary summary;
    private List<String> sites;

    SiteImportWorkerTask(IExtensionHelpers helpers, IBurpExtenderCallbacks callbacks, IListScannerLogger logger, ISiteImportSummary summary, List<String> sites, SiteImportSettings settings) {
        this.logger = logger;
        this.summary = summary;
        this.sites = sites;
        this.helpers = helpers;
        this.callbacks = callbacks;
        this.settings = settings;
    }

    @Override
    public Void doInBackground() {

        ThreadPoolExecutor executor = (ThreadPoolExecutor) Executors.newFixedThreadPool(10);

        for (String site : this.sites) {
            UrlCallRunner urlCall = new UrlCallRunner(this.helpers, this.callbacks, this.logger, this.summary, site, this.settings);
            executor.execute(urlCall);
        }

        long totalTasks = executor.getTaskCount();

        while (executor.getCompletedTaskCount() < totalTasks) {
            try {
                Thread.sleep(100);

                setProgress((int) ((executor.getCompletedTaskCount() * 100) / executor.getTaskCount()));
            } catch (InterruptedException e) {
                logger.Log("Stop Requested");
                executor.shutdown();
                try {
                    executor.awaitTermination(1, TimeUnit.SECONDS);
                } catch (InterruptedException e1) {
                    e1.printStackTrace();
                }
                logger.Log("Stopping NOW");
                executor.shutdownNow();
                break;
            }
        }

        executor.shutdown();
        firePropertyChange("completed", false, true);

        return null;
    }
}