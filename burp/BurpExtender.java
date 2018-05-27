package burp;

import javax.swing.*;
import javax.swing.border.BevelBorder;
import javax.swing.border.EmptyBorder;
import javax.swing.border.LineBorder;
import javax.swing.filechooser.FileNameExtensionFilter;
import javax.swing.text.BadLocationException;
import javax.swing.text.DefaultCaret;
import java.awt.*;
import java.awt.event.ActionEvent;
import java.io.*;
import java.net.MalformedURLException;
import java.net.URL;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.concurrent.Executors;
import java.util.concurrent.ThreadPoolExecutor;

import static java.awt.GridBagConstraints.NORTH;

public class BurpExtender implements IBurpExtender, ITab
{
    private IBurpExtenderCallbacks callbacks;
    private IExtensionHelpers helpers;
    private JPanel panel;
    private JCheckBox jSpiderCheckBox;
    private JCheckBox jAddToScopeCheckBox;
    private JCheckBox jFollowRedirectCheckbox;
    private JTextArea jLogArea;
    private DefaultListModel<String> siteListModel = new DefaultListModel<String>();
    private JList jSiteList;
    private IListScannerLogger logger;

    private static final int MAX_SITE = 100;

    @Override
    public void registerExtenderCallbacks(IBurpExtenderCallbacks callbacks)
    {
        this.callbacks = callbacks;
        this.helpers = callbacks.getHelpers();

        callbacks.setExtensionName("Site Import Extension");

        SwingUtilities.invokeLater(() -> {
            panel = new JPanel(new GridBagLayout());
            panel.setBorder(new EmptyBorder(15, 15, 15, 15));

            Font defaultFont = (Font)UIManager.getLookAndFeelDefaults().get("defaultFont");

            GridBagConstraints gbc = new GridBagConstraints();
            gbc.weightx = 0;
            gbc.weighty = 0;
            gbc.insets = new Insets(3,3,3,3);

            JLabel titleLabel = new JLabel("Site Import");
            titleLabel.setFont(new Font("Tahoma", Font.BOLD, (int) (defaultFont.getSize() * 1.2)));
            titleLabel.setForeground(new Color(235,102,51));
            gbc.gridx = 0;
            gbc.gridy = 0;
            gbc.fill = GridBagConstraints.HORIZONTAL;
            panel.add(titleLabel, gbc);

            // Loading area
            JButton jLoadButton = new JButton ("Load Sites");
            gbc.gridx = 0;
            gbc.gridy = 1;
            gbc.fill = GridBagConstraints.HORIZONTAL;
            jLoadButton.addActionListener(this::jButtonLoadClicked);
            panel.add(jLoadButton, gbc);

            jSiteList = new JList(siteListModel);
            JScrollPane jSiteListScrollPane = new JScrollPane(jSiteList);
            gbc.gridwidth = 2;
            gbc.gridx = 1;
            gbc.gridy = 2;
            gbc.weightx = 0;
            gbc.weighty = 1;
            gbc.fill = GridBagConstraints.BOTH;
            panel.add(jSiteListScrollPane, gbc);

            JButton jImportButton = new JButton ("Import to Site List");
            gbc.gridwidth = 1;
            gbc.gridx = 0;
            gbc.gridy = 3;
            gbc.weightx = 0;
            gbc.weighty = 0;
            gbc.anchor = NORTH;
            jImportButton.addActionListener(this::jButtonImportClicked);
            panel.add(jImportButton, gbc);

            jSpiderCheckBox = new JCheckBox("Spider URLs");
            gbc.gridwidth = 1;
            gbc.gridx = 1;
            gbc.gridy = 3;

            gbc.fill = GridBagConstraints.HORIZONTAL;
            panel.add(jSpiderCheckBox, gbc);

            jAddToScopeCheckBox = new JCheckBox("Add to Scope");
            gbc.gridx = 1;
            gbc.gridy = 4;
            gbc.fill = GridBagConstraints.HORIZONTAL;
            panel.add(jAddToScopeCheckBox, gbc);

            jFollowRedirectCheckbox = new JCheckBox("Follow Redirections");
            gbc.gridx = 2;
            gbc.gridy = 3;
            gbc.fill = GridBagConstraints.HORIZONTAL;
            panel.add(jFollowRedirectCheckbox, gbc);

            JLabel jLogLabel = new JLabel("Log");
            gbc.gridx = 1;
            gbc.gridy = 5;
            gbc.fill = GridBagConstraints.HORIZONTAL;
            panel.add(jLogLabel, gbc);

            jLogArea = new JTextArea ();
            JScrollPane sp = new JScrollPane(jLogArea);
            DefaultCaret caret = (DefaultCaret) jLogArea.getCaret();
            caret.setUpdatePolicy(DefaultCaret.ALWAYS_UPDATE);
            gbc.gridwidth = 2;
            gbc.gridx = 1;
            gbc.gridy = 6;
            gbc.weightx = 1;
            gbc.weighty = 1;
            gbc.fill = GridBagConstraints.BOTH;
            panel.add(sp, gbc);

            this.logger = new ListScannerLogger(jLogArea);

            callbacks.addSuiteTab(BurpExtender.this);
        });

    }

    private void jButtonLoadClicked(ActionEvent actionEvent) {

        JFileChooser fileChooser = new JFileChooser("Import Sites");
        FileNameExtensionFilter filter = new FileNameExtensionFilter("Text Files", "txt");
        fileChooser.setFileFilter(filter);

        if (fileChooser.showOpenDialog(this.getUiComponent()) != JFileChooser.APPROVE_OPTION) {
            return;
        }

        File file = fileChooser.getSelectedFile();
        jLogArea.append("Loading " + file.getName() + "\n");

        int lineCount = 0;

        try(BufferedReader br = new BufferedReader(new FileReader(file.getAbsoluteFile()))) {
            String line = br.readLine();

            while (line != null) {
                lineCount++;

                siteListModel.addElement(line);
                line = br.readLine();

                if (lineCount == MAX_SITE){
                    JOptionPane.showMessageDialog(this.getUiComponent(), "Max site limit " + MAX_SITE + " reached");
                    break;
                }
            }

            jLogArea.append(lineCount + " sites loaded" + System.lineSeparator());
        } catch (FileNotFoundException e) {
            jLogArea.append("File not found: " + file.getName() + System.lineSeparator());
            jLogArea.append("File not found: " + file.getName() + System.lineSeparator());
        } catch (IOException e) {
            jLogArea.append("Error reading file: " + file.getName() + System.lineSeparator());
        }
    }

    private void jButtonImportClicked(ActionEvent actionEvent) {

        // text area could be quite big, so rather than loading it all into an array based on \n
        // let's just grab each line as we need it
        try{
            int numberOfSites = validateFileSites(siteListModel);

            if (numberOfSites > MAX_SITE){
                JOptionPane.showMessageDialog(this.getUiComponent(), "Max site limit " + MAX_SITE + " reached");
                return;
            }

            List<String> sites = new ArrayList<>();

            for (int i = 0; i<siteListModel.size();i++){
                sites.add(siteListModel.get(i));
            }

            SiteImportSettings settings = new SiteImportSettings();
            settings.followRedirects = jFollowRedirectCheckbox.isSelected();
            settings.deepScan = jSpiderCheckBox.isSelected();
            settings.addToScope = jAddToScopeCheckBox.isSelected();

            allocateSitesToThreads(sites, settings);


        } catch (FileValidationException ex){
            jLogArea.append(ex.getMessage() + System.lineSeparator());
        }

    }

    private void allocateSitesToThreads(List<String> sites, SiteImportSettings settings) {
        new Thread(new UrlCallThreadManager(this.helpers, this.callbacks, this.logger, sites, settings)).start();
    }


    private int validateFileSites(DefaultListModel siteListModel) throws FileValidationException {

        int lineCount = siteListModel.getSize();
        int populatedLines = 0;

        String line;

        for(int i = 0; i < lineCount; i ++){
            line = (String)siteListModel.getElementAt(i);

            if (line.trim().length() == 0){
                continue;
            }

            if (!validateLine(line)) {
                throw new FileValidationException("Error in line " + (i + 1));
            }

            populatedLines ++;

        }

        return populatedLines;
    }

    private boolean validateLine (String line)
    {
        try {
            new URL(line);
            return true;
        } catch (MalformedURLException e) {
            return false;
        }
    }



    @Override
    public String getTabCaption() {
        return "Scope Scanner";
    }

    @Override
    public Component getUiComponent() {
        return panel;
    }
}