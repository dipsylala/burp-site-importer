import burp.IListScannerLogger;
import burp.NessusFileImporter;
import burp.OpenVasFileImporter;

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
            assert sites.size() == 1;
            assert sites.get(0).equals("https://127.0.0.1:443");
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