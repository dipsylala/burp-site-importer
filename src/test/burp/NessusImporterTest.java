package burp;

import java.io.File;
import java.net.URISyntaxException;
import java.util.List;

public class NessusImporterTest {

    @org.junit.Test
    public void shouldDetectInvalidFile() {

        IListScannerLogger logger = createMockScannerLogger();

        NessusFileImporter sut = new NessusFileImporter(logger);

        try {
            File file = new File(getClass().getResource("/invalidfile.nessus").toURI());
            boolean result = sut.canParseFile(file);
            assert !result;
        } catch (URISyntaxException e) {
            e.printStackTrace();
        }
    }

    @org.junit.Test
    public void shouldDetectValidFile() {

        IListScannerLogger logger = createMockScannerLogger();

        NessusFileImporter sut = new NessusFileImporter(logger);

        try {
            File file = new File(getClass().getResource("/validscan.nessus").toURI());
            boolean result = sut.canParseFile(file);
            assert result;
        } catch (URISyntaxException e) {
            e.printStackTrace();
        }
    }


    @org.junit.Test
    public void validNessusFileShouldLoad() {

        IListScannerLogger logger = createMockScannerLogger();

        NessusFileImporter sut = new NessusFileImporter(logger);

        try {
            File file = new File(getClass().getResource("/validscan.nessus").toURI());
            List<String> sites = sut.loadFile(file);
            assert sites.size() == 2;
            assert sites.get(0).equals("https://10.0.0.2:8834/html5.html");
            assert sites.get(1).equals("http://10.0.0.2:80");
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