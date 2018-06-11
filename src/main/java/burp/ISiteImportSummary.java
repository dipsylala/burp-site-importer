public interface ISiteImportSummary {
    void addUnreachableSite (String site);
    void addBadURL(String site);
    String toString();
    void clear();
}
