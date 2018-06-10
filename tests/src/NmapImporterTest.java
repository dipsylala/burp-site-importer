import burp.IListScannerLogger;
import burp.NmapFileImporter;

import java.io.File;
import java.net.URISyntaxException;
import java.util.List;

public class NmapImporterTest {
    @org.junit.Test
    public void shortValidFileShouldLoad() {

        IListScannerLogger logger = createMockScannerLogger();

        NmapFileImporter sut = new NmapFileImporter(logger);

        try {
            File file = new File(getClass().getResource("/simplescan.xml").toURI());
            List<String> sites = sut.loadFile(file);
            assert sites.size() == 2;
            assert sites.get(0).equals("http://www.microsoft.com:80");
            assert sites.get(1).equals("https://www.microsoft.com:443");
        } catch (URISyntaxException e) {
            e.printStackTrace();
        }
    }

    @org.junit.Test
    public void longValidFileShouldLoad() {
        IListScannerLogger logger = createMockScannerLogger();
        NmapFileImporter sut = new NmapFileImporter(logger);

        try {
            File file = new File(getClass().getResource("/complexscan.xml").toURI());
            List<String> sites = sut.loadFile(file);

            assert sites.size() == 2;
            assert sites.get(0).equals("http://www.microsoft.com:80");
            assert sites.get(1).equals("https://www.microsoft.com:443");
        } catch (URISyntaxException e) {
            e.printStackTrace();
        }
    }

    private IListScannerLogger createMockScannerLogger(){
        return new IListScannerLogger() {
            @Override
            public void log(String message) {

            }

            @Override
            public void clear() {

            }
        };
    }
}