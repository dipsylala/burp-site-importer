import java.io.File;
import java.net.URISyntaxException;
import java.util.List;

public class OpenVasImporterTest {

    @org.junit.Test
    public void shouldDetectInvalidFile() {

        IListScannerLogger logger = createMockScannerLogger();

        OpenVasFileImporter sut = new OpenVasFileImporter(logger);

        try {
            File file = new File(getClass().getResource("/src/test/resources/invalidopenvasfile.xml").toURI());
            boolean result = sut.canParseFile(file);
            assert !result;
        } catch (URISyntaxException e) {
            e.printStackTrace();
        }
    }

    @org.junit.Test
    public void shouldDetectValidFile() {

        IListScannerLogger logger = createMockScannerLogger();

        OpenVasFileImporter sut = new OpenVasFileImporter(logger);

        try {
            File file = new File(getClass().getResource("/src/test/resources/openvas.xml").toURI());
            boolean result = sut.canParseFile(file);
            assert result;
        } catch (URISyntaxException e) {
            e.printStackTrace();
        }
    }


    @org.junit.Test
    public void validOpenVasFileShouldLoad() {

        IListScannerLogger logger = createMockScannerLogger();

        OpenVasFileImporter sut = new OpenVasFileImporter(logger);

        try {
            File file = new File(getClass().getResource("/src/test/resources/openvas.xml").toURI());
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