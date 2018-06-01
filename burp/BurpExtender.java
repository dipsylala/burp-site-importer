package burp;

import javax.imageio.ImageIO;
import javax.swing.*;
import javax.swing.border.Border;
import javax.swing.border.EmptyBorder;
import javax.swing.filechooser.FileNameExtensionFilter;
import javax.swing.plaf.basic.BasicSplitPaneDivider;
import javax.swing.plaf.basic.BasicSplitPaneUI;
import javax.swing.text.DefaultCaret;
import java.awt.*;
import java.awt.datatransfer.DataFlavor;
import java.awt.datatransfer.UnsupportedFlavorException;
import java.awt.event.ActionEvent;
import java.awt.event.FocusEvent;
import java.awt.event.FocusListener;
import java.beans.PropertyChangeEvent;
import java.beans.PropertyChangeListener;
import java.io.*;
import java.util.ArrayList;
import java.util.List;

import static java.awt.GridBagConstraints.NORTH;

public class BurpExtender implements IBurpExtender, ITab, PropertyChangeListener
{
    private IBurpExtenderCallbacks callbacks;
    private IExtensionHelpers helpers;
    private ISiteImportSummary siteImportSummary;
    private JPanel panel;
    private JCheckBox jSpiderCheckBox;
    private JCheckBox jAddToScopeCheckBox;
    private JCheckBox jFollowRedirectCheckbox;
    private DefaultListModel<String> siteListModel = new DefaultListModel<>();
    private JList<String> jSiteList;
    private JTextField jAddSiteText;
    private IListScannerLogger logger;
    private ProgressMonitor progressMonitor;
    private SiteImportWorker siteImportWorkerTask;

    private static final Color BURPSUITE_ORANGE = new Color (255,102,51);

    private static void flattenSplitPane(JSplitPane jSplitPane) {

        jSplitPane.setUI(new BasicSplitPaneUI() {
            public BasicSplitPaneDivider createDefaultDivider() {
                return new BasicSplitPaneDivider(this) {
                    public void setBorder(Border b) {

                    }

                    public void paint(Graphics var1) {
                        int[] coordX = new int[3];
                        int[] coordY = new int[3];
                        var1.setColor(this.getBackground());
                        var1.fillRect(0, 0, this.getWidth(), this.getHeight());
                        if (this.orientation == JSplitPane.VERTICAL_SPLIT) {
                            int minHeight = Math.min(this.getHeight(), 10);
                            int offset = (this.getHeight() / 2) - (minHeight / 2);

                            coordX[0] = offset + minHeight;
                            coordY[0] = minHeight;

                            coordX[1] = offset + (minHeight * 2);
                            coordY[1] = 0;

                            coordX[2] = offset;
                            coordY[2] = 0;
                        } else {
                            int minWidth = Math.min(this.getWidth(), 10);
                            int offset = (this.getHeight() / 2) - (minWidth / 2);

                            coordX[0] = 0;
                            coordY[0] = offset;

                            coordX[1] = minWidth;
                            coordY[1] = (minWidth / 2) + offset;

                            coordX[2] = 0;
                            coordY[2] = offset + minWidth;
                        }

                        var1.setColor(BURPSUITE_ORANGE);
                        var1.fillPolygon(coordX, coordY, 3);
                    }
                };
            }
        });

        jSplitPane.setBorder(null);
    }

    private GridBagConstraints getDefaultGridBagConstraints(){
        GridBagConstraints gbc = new GridBagConstraints();
        gbc.insets = new Insets(3,3,3,3);
        return gbc;
    }

    @Override
    public void registerExtenderCallbacks(IBurpExtenderCallbacks callbacks)
    {
        this.callbacks = callbacks;
        this.helpers = callbacks.getHelpers();

        callbacks.setExtensionName("Site Import Extension");

        SwingUtilities.invokeLater(
            this::createUI
        );
    }

    private void jAddSiteButtonClicked(ActionEvent actionEvent) {
        String site = jAddSiteText.getText().trim();
        if (site.length() == 0){
            return;
        }

        siteListModel.addElement(site);
        jAddSiteText.setText("");
    }

    private void jClearButtonClicked(ActionEvent actionEvent) {
        siteListModel.removeAllElements();
        this.logger.log("Sites cleared");
    }

    private void jButtonClearLogClicked(ActionEvent actionEvent) {
        this.logger.clear();
    }

    private void jPasteURLButtonClicked(ActionEvent actionEvent) {
        String data;
        try {
            data = (String) Toolkit.getDefaultToolkit().getSystemClipboard().getData(DataFlavor.stringFlavor);
        } catch (UnsupportedFlavorException e) {
            this.logger.log("No text available");
            return;
        } catch (IOException e) {
            this.logger.log("Could not read from clipboard");
            return;
        }

        int lineCount = 0;

        String[] sites = data.split("\n");
        for (String site : sites){
            String trimmedSite = site.trim();
            if (trimmedSite.length() == 0){
                continue;
            }

            lineCount ++;
            siteListModel.addElement(trimmedSite);
        }

        this.logger.log(lineCount + " sites loaded from clipboard");
    }

    private void jRemoveButtonClicked(ActionEvent actionEvent) {
        int index = this.jSiteList.getSelectedIndices().length - 1;

        while (this.jSiteList.getSelectedIndices().length != 0) {
            siteListModel.removeElementAt(this.jSiteList.getSelectedIndices()[index--]);
        }
    }

    private void jButtonLoadClicked(ActionEvent actionEvent) {

        JFileChooser fileChooser = new JFileChooser("Import Sites");
        FileNameExtensionFilter filter = new FileNameExtensionFilter("Text Files", "txt");
        fileChooser.setFileFilter(filter);

        if (fileChooser.showOpenDialog(this.panel) != JFileChooser.APPROVE_OPTION) {
            return;
        }

        File file = fileChooser.getSelectedFile();
        this.logger.log("Loading " + file.getName());

        int lineCount = 0;

        try(BufferedReader br = new BufferedReader(new FileReader(file.getAbsoluteFile()))) {
            String line = br.readLine();

            while (line != null) {
                line = line.trim();
                if (line.length() > 0) {
                    lineCount++;

                    siteListModel.addElement(line);
                }

                line = br.readLine();
            }

            this.logger.log(lineCount + " sites loaded");
        } catch (FileNotFoundException e) {
            this.logger.log("File not found: " + file.getName());
            this.logger.log("File not found: " + file.getName());
        } catch (IOException e) {
            this.logger.log("Error reading file: " + file.getName());
        }
    }

    private void jButtonHelpClicked(ActionEvent actionEvent) {

        InputStream is = this.getClass().getResourceAsStream("/resources/help.html");
        java.util.Scanner s = new java.util.Scanner(is).useDelimiter("\\A");
        String helpText = s.next();
        new PopUpHelp(helpText, (Component)actionEvent.getSource());
    }


    private void jButtonImportClicked(ActionEvent actionEvent) {

        List<String> sites = new ArrayList<>();

        for (int i = 0; i < siteListModel.size(); i++) {
            sites.add(siteListModel.get(i));
        }

        siteImportSummary = new SiteImportSummary();

        SiteImportSettings settings = new SiteImportSettings();
        settings.followRedirects = jFollowRedirectCheckbox.isSelected();
        settings.deepScan = jSpiderCheckBox.isSelected();
        settings.addToScope = jAddToScopeCheckBox.isSelected();

        createAndShowSiteWorker(sites, settings);
    }

    private void createAndShowSiteWorker(List<String> sites, SiteImportSettings settings) {

        setPanelEnabledStatus(false);

        progressMonitor = new ProgressMonitor(this.panel,
                "Importing sites",
                "", 0, 100);

        progressMonitor.setProgress(0);
        progressMonitor.setNote("");

        siteImportWorkerTask = new SiteImportWorker(helpers, callbacks, logger, siteImportSummary,  sites, settings);
        siteImportWorkerTask.addPropertyChangeListener(this);
        siteImportWorkerTask.execute();
    }

    @Override
    public String getTabCaption() {
        return "List Scanner";
    }

    @Override
    public Component getUiComponent() {
        return panel;
    }

    @Override
    public void propertyChange(PropertyChangeEvent evt) {

        String propertyChange = evt.getPropertyName();

        if (propertyChange.equals("progress")){
            int progress = (Integer) evt.getNewValue();
            progressMonitor.setProgress(progress);
        }

        if (propertyChange.equals("completed")){
            logger.log("------------------------------------" + System.lineSeparator() +
                       "Import Summary   "  + System.lineSeparator() +
                       "------------------------------------" + System.lineSeparator());

            logger.log(siteImportSummary.toString());
            setPanelEnabledStatus(true);
        }

        if (propertyChange.equals("taskscompleted")){
            ProgressMessage progressMessage = (ProgressMessage)evt.getNewValue();
            progressMonitor.setNote(progressMessage.completed + "/" + progressMessage.total);
        }

        if (progressMonitor.isCanceled() || siteImportWorkerTask.isDone()) {
            if (progressMonitor.isCanceled()) {
                siteImportWorkerTask.cancel(true);
            }
        }
    }

    private void setPanelEnabledStatus(boolean enabled){
        Component[] components = panel.getComponents();

        // Don't need to recurse - it's a simple panel for the moment
        for (Component component : components) {
            component.setEnabled(enabled);
        }
    }

    private void createUI() {
        this.panel = new JPanel(new GridBagLayout());
        this.panel.setBorder(new EmptyBorder(15, 15, 15, 15));

        Font defaultFont = (Font) UIManager.getLookAndFeelDefaults().get("defaultFont");
        GridBagConstraints gbc = getDefaultGridBagConstraints();

        try {
            JButton jHelpButton = new JButton("");
            jHelpButton.setFocusPainted(false);
            jHelpButton.setPreferredSize(new Dimension(30, 30));
            InputStream is = getClass().getResourceAsStream("/resources/question_mark.png");
            Image image = ImageIO.read(is);
            Image resizedImage = image.getScaledInstance(14, 18,Image.SCALE_SMOOTH );
            jHelpButton.setIcon(new ImageIcon(resizedImage));
            jHelpButton.addActionListener(this::jButtonHelpClicked);

            gbc = getDefaultGridBagConstraints();
            gbc.gridx = 0;
            gbc.gridy = 0;
            this.panel.add(jHelpButton, gbc);

        } catch (IOException e) {
            e.printStackTrace();
        }

        JLabel titleLabel = new JLabel("Site Import");
        titleLabel.setFont(new Font("Tahoma", Font.BOLD, (int) (defaultFont.getSize() * 1.2)));
        titleLabel.setForeground(BURPSUITE_ORANGE);
        gbc.gridx = 1;
        gbc.gridy = 0;
        gbc.fill = GridBagConstraints.HORIZONTAL;
        this.panel.add(titleLabel, gbc);

        // Site List Buttons
        JButton jPasteURLButton = new JButton("Paste");
        gbc = getDefaultGridBagConstraints();
        gbc.gridx = 1;
        gbc.gridy = 1;
        gbc.fill = GridBagConstraints.HORIZONTAL;
        jPasteURLButton.addActionListener(this::jPasteURLButtonClicked);
        this.panel.add(jPasteURLButton, gbc);

        // Loading area
        JButton jLoadButton = new JButton("Load ...");
        gbc = getDefaultGridBagConstraints();
        gbc.gridx = 1;
        gbc.gridy = 2;
        gbc.fill = GridBagConstraints.HORIZONTAL;
        jLoadButton.addActionListener(this::jButtonLoadClicked);
        this.panel.add(jLoadButton, gbc);

        JButton jRemoveButton = new JButton("Remove");
        gbc = getDefaultGridBagConstraints();
        gbc.gridx = 1;
        gbc.gridy = 3;
        gbc.fill = GridBagConstraints.HORIZONTAL;
        jRemoveButton.addActionListener(this::jRemoveButtonClicked);
        this.panel.add(jRemoveButton, gbc);

        JButton jClearButton = new JButton("Clear");
        gbc = getDefaultGridBagConstraints();
        gbc.gridx = 1;
        gbc.gridy = 4;
        gbc.fill = GridBagConstraints.HORIZONTAL;
        jClearButton.addActionListener(this::jClearButtonClicked);
        this.panel.add(jClearButton, gbc);

        // Site List area
        JPanel jSiteListPadder = new JPanel();

        jSiteList = new JList<>(siteListModel);
        JScrollPane jSiteListScrollPane = new JScrollPane(jSiteList);
        JSplitPane jSiteListSplitPane = new JSplitPane();
        jSiteListSplitPane.setLeftComponent(jSiteListScrollPane);
        jSiteListSplitPane.setRightComponent(jSiteListPadder);
        jSiteListSplitPane.setDividerLocation(300);
        jSiteListSplitPane.setOneTouchExpandable(false);
        jSiteListSplitPane.setDividerSize(10);
        jSiteListSplitPane.setMinimumSize(new Dimension(100, 100));

        flattenSplitPane(jSiteListSplitPane);
        gbc = getDefaultGridBagConstraints();
        gbc.gridheight = 5;
        gbc.gridwidth = 3;
        gbc.gridx = 2;
        gbc.gridy = 1;
        gbc.weightx = 0;
        gbc.weighty = 1;
        gbc.fill = GridBagConstraints.BOTH;

        this.panel.add(jSiteListSplitPane, gbc);

        JButton jAddSiteButton = new JButton("Add");
        gbc = getDefaultGridBagConstraints();
        gbc.gridx = 1;
        gbc.gridy = 6;
        gbc.fill = GridBagConstraints.HORIZONTAL;
        jAddSiteButton.addActionListener(this::jAddSiteButtonClicked);
        this.panel.add(jAddSiteButton, gbc);

        jAddSiteText = new JTextField("Enter a new item");
        jAddSiteText.setForeground(Color.GRAY);
        jAddSiteText.addFocusListener(new FocusListener() {
            @Override
            public void focusGained(FocusEvent e) {
                if (jAddSiteText.getText().equals("Enter a new item")) {
                    jAddSiteText.setText("");
                    jAddSiteText.setForeground(Color.BLACK);
                }
            }

            @Override
            public void focusLost(FocusEvent e) {
                if (jAddSiteText.getText().isEmpty()) {
                    jAddSiteText.setForeground(Color.GRAY);
                    jAddSiteText.setText("Enter a new item");
                }
            }
        });

        gbc = getDefaultGridBagConstraints();
        gbc.gridwidth = 2;
        gbc.gridx = 2;
        gbc.gridy = 6;
        gbc.fill = GridBagConstraints.HORIZONTAL;
        this.panel.add(jAddSiteText, gbc);

        JButton jImportButton = new JButton("Import to Site List");
        gbc = getDefaultGridBagConstraints();
        gbc.gridx = 1;
        gbc.gridy = 9;
        gbc.anchor = NORTH;
        jImportButton.addActionListener(this::jButtonImportClicked);
        this.panel.add(jImportButton, gbc);

        jSpiderCheckBox = new JCheckBox("Spider URLs");
        gbc = getDefaultGridBagConstraints();
        gbc.gridx = 2;
        gbc.gridy = 7;
        gbc.fill = GridBagConstraints.HORIZONTAL;
        this.panel.add(jSpiderCheckBox, gbc);

        jAddToScopeCheckBox = new JCheckBox("Add to Scope");
        gbc = getDefaultGridBagConstraints();
        gbc.gridx = 2;
        gbc.gridy = 8;
        gbc.fill = GridBagConstraints.HORIZONTAL;
        this.panel.add(jAddToScopeCheckBox, gbc);

        jFollowRedirectCheckbox = new JCheckBox("Follow Redirections");
        gbc = getDefaultGridBagConstraints();
        gbc.gridx = 3;
        gbc.gridy = 7;
        gbc.fill = GridBagConstraints.HORIZONTAL;
        this.panel.add(jFollowRedirectCheckbox, gbc);

        // Log area
        JLabel jLogLabel = new JLabel("Log");
        gbc = getDefaultGridBagConstraints();
        gbc.gridx = 2;
        gbc.gridy = 10;
        gbc.fill = GridBagConstraints.HORIZONTAL;
        this.panel.add(jLogLabel, gbc);

        JButton jClearLogButton = new JButton("Clear");
        gbc = getDefaultGridBagConstraints();
        gbc.gridx = 1;
        gbc.gridy = 11;
        gbc.fill = GridBagConstraints.HORIZONTAL;
        gbc.anchor = NORTH;
        jClearLogButton.addActionListener(this::jButtonClearLogClicked);
        this.panel.add(jClearLogButton, gbc);

        JTextArea jLogArea = new JTextArea();
        jLogArea.setEditable(false);
        JScrollPane jLogAreaScrollPanel = new JScrollPane(jLogArea);
        DefaultCaret caret = (DefaultCaret) jLogArea.getCaret();
        caret.setUpdatePolicy(DefaultCaret.ALWAYS_UPDATE);

        JPanel jLogAreaPadder = new JPanel();

        JSplitPane jLogAreaSplitPane = new JSplitPane();
        jLogAreaSplitPane.setLeftComponent(jLogAreaScrollPanel);
        jLogAreaSplitPane.setRightComponent(jLogAreaPadder);
        jLogAreaSplitPane.setDividerLocation(500);
        jLogAreaSplitPane.setOneTouchExpandable(false);
        jLogAreaSplitPane.setDividerSize(10);
        jLogAreaSplitPane.setMinimumSize(new Dimension(100, 100));

        flattenSplitPane(jLogAreaSplitPane);
        gbc = getDefaultGridBagConstraints();

        gbc.gridheight = 1;
        gbc.gridwidth = 3;
        gbc.gridx = 2;
        gbc.gridy = 11;
        gbc.weightx = 1;
        gbc.weighty = 1;
        gbc.fill = GridBagConstraints.BOTH;
        this.panel.add(jLogAreaSplitPane, gbc);

        this.logger = new ListScannerLogger(jLogArea);

        this.callbacks.addSuiteTab(BurpExtender.this);

    }
}