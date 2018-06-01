package burp;

import javax.swing.*;
import java.util.List;
import java.util.concurrent.Executors;
import java.util.concurrent.ThreadPoolExecutor;
import java.util.concurrent.TimeUnit;

public class SiteImportWorker extends SwingWorker<Void, Void> {

    private IExtensionHelpers helpers;
    private IBurpExtenderCallbacks callbacks;
    private SiteImportSettings settings;
    private IListScannerLogger logger;
    private ISiteImportSummary summary;
    private List<String> sites;

    SiteImportWorker(IExtensionHelpers helpers,
                     IBurpExtenderCallbacks callbacks,
                     IListScannerLogger logger,
                     ISiteImportSummary summary,
                     List<String> sites,
                     SiteImportSettings settings) {
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
            SiteCallRunnable urlCall = new SiteCallRunnable(this.helpers, this.callbacks, this.logger, this.summary, site, this.settings);
            executor.execute(urlCall);
        }

        long totalTasks = executor.getTaskCount();

        int lastPercentage = 0;
        long lastTaskCount = 0;

        ProgressMessage progressMessage = new ProgressMessage();
        progressMessage.total = totalTasks;

        while (executor.getCompletedTaskCount() < totalTasks) {
            try {
                Thread.sleep(100);

                long taskCount = executor.getCompletedTaskCount();
                int newPercentage = (int)((taskCount * 100) / totalTasks);

                if (taskCount!=lastTaskCount){
                    progressMessage.completed = taskCount;
                    firePropertyChange(Constants.SITE_COMPLETED, null, progressMessage);
                    lastTaskCount = taskCount;
                }

                if (newPercentage!= lastPercentage){
                    setProgress(newPercentage);
                    lastPercentage = newPercentage;
                }

            } catch (InterruptedException e) {
                logger.log("Stop Requested");
                executor.shutdown();
                try {
                    executor.awaitTermination(1, TimeUnit.SECONDS);
                } catch (InterruptedException e1) {
                    e1.printStackTrace();
                }
                logger.log("Stopping NOW");
                executor.shutdownNow();
                break;
            }
        }

        if (!executor.isShutdown()){
            executor.shutdown();
        }

        firePropertyChange(Constants.ALL_SITES_COMPLETED, false, true);

        return null;
    }
}