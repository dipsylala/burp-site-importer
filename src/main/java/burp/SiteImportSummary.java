package burp;

import java.util.ArrayList;
import java.util.List;

public class SiteImportSummary implements ISiteImportSummary {

    private final List<String> unreachableSites;
    private final List<String> badURLs;

    SiteImportSummary(){
        this.unreachableSites = new ArrayList<>();
        this.badURLs = new ArrayList<>();
    }

    public synchronized void addUnreachableSite (String site){
        this.unreachableSites.add(site);
    }

    public synchronized void addBadURL(String site){
        this.badURLs.add(site);
    }

    public synchronized void clear(){
        this.badURLs.clear();
        this.unreachableSites.clear();
    }

    public synchronized String toString(){
        StringBuilder sb = new StringBuilder();

        sb.append("Bad URLS: ").append(System.lineSeparator());

        if (this.badURLs.isEmpty()) {
            sb.append("None").append(System.lineSeparator());
        } else {
            for (String site : this.badURLs) {
                sb.append(site).append(System.lineSeparator());
            }
        }

        sb.append("Unreachable Sites: ").append(System.lineSeparator());
        if (this.unreachableSites.isEmpty()) {
            sb.append("None").append(System.lineSeparator());
        } else {
            for (String site : this.unreachableSites) {
                sb.append(site).append(System.lineSeparator());
            }
        }

        return sb.toString();
    }
}
