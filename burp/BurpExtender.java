package burp;

import javax.swing.*;
import javax.swing.filechooser.FileNameExtensionFilter;
import java.awt.*;
import java.awt.event.ActionEvent;
import java.io.*;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

public class BurpExtender implements IBurpExtender, ITab
{
    private IBurpExtenderCallbacks callbacks;
    private IExtensionHelpers helpers;
    private JPanel panel;
    private JCheckBox jSpiderCheckBox;
    private JCheckBox jAddToScopeCheckBox;
    private JTextArea jSiteListTextArea;

    @Override
    public void registerExtenderCallbacks(IBurpExtenderCallbacks callbacks)
    {
        this.callbacks = callbacks;
        this.helpers = callbacks.getHelpers();

        callbacks.setExtensionName("Scope Scanner Extension");

        SwingUtilities.invokeLater(() -> {
            panel = new JPanel();

            JButton jLoadButton = new JButton("Import List");
            jLoadButton.addActionListener(this::jButtonLoadClicked);
            panel.add(jLoadButton);

            jSiteListTextArea = new JTextArea();
            panel.add(jSiteListTextArea);


            jSpiderCheckBox = new JCheckBox("Spider URLs");
            panel.add(jSpiderCheckBox);

            jAddToScopeCheckBox = new JCheckBox("Add to Scope");
            panel.add(jAddToScopeCheckBox);


            JButton jButtonStart = new JButton("Touch");
            jButtonStart.addActionListener(this::jButtonStartClicked);
            panel.add(jButtonStart);


            callbacks.addSuiteTab(BurpExtender.this);
        });

    }

    private void jButtonLoadClicked(ActionEvent actionEvent) {

        JFileChooser fileChooser = new JFileChooser("Import Sites");
        FileNameExtensionFilter filter = new FileNameExtensionFilter("Text Files", "txt");
        fileChooser.setFileFilter(filter);

        int returnVal = fileChooser.showOpenDialog(this.getUiComponent());

        if(returnVal == JFileChooser.APPROVE_OPTION) {

            readFileIntoTextArea(fileChooser);
        }
    }

    private void readFileIntoTextArea(JFileChooser fileChooser) {
        jSiteListTextArea.setText("");

        String line;
        File file = fileChooser.getSelectedFile();

        try {
            FileReader fr = new FileReader(file.getAbsoluteFile());
            BufferedReader reader = new BufferedReader(fr);


            while ((line = reader.readLine()) != null){
                jSiteListTextArea.append(line + "\n");

            }

        } catch (FileNotFoundException e) {
            e.printStackTrace();
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    private void jButtonStartClicked(java.awt.event.ActionEvent evt)  {

        String s[] = jSiteListTextArea.getText().split("\\r?\\n");
        List<String> sites = new ArrayList<>(Arrays.asList(s)) ;

        boolean addToScope = jAddToScopeCheckBox.isSelected();
        boolean spider = jSpiderCheckBox.isSelected();

        new Thread(new UrlCallRunner(this.helpers, this.callbacks, sites,  addToScope, spider)).start();
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