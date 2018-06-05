package burp;

import javax.swing.*;
import javax.swing.border.Border;
import javax.swing.border.EmptyBorder;
import javax.swing.text.DefaultCaret;
import javax.swing.text.Document;
import javax.swing.text.html.HTMLEditorKit;
import javax.swing.text.html.StyleSheet;
import java.awt.*;
import java.awt.event.WindowAdapter;
import java.awt.event.WindowEvent;
import java.io.*;

import static java.awt.GridBagConstraints.NORTH;

class BurpPopUpHelp {

    BurpPopUpHelp(String title, String body, Component baseComponent) {

        // Configure the Header Area
        JEditorPane jHeaderEditorPane = new JEditorPane();
        jHeaderEditorPane.setEditable(false);

        HTMLEditorKit headerEditorKit = new HTMLEditorKit();
        jHeaderEditorPane.setEditorKit(headerEditorKit);

        // Configure the Content Area
        JEditorPane jContentEditorPane = new JEditorPane();
        jContentEditorPane.setEditable(false);

        JScrollPane contentScrollPane = new JScrollPane(jContentEditorPane);
        contentScrollPane.setAutoscrolls(false);
        contentScrollPane.setViewportBorder(null);

        HTMLEditorKit contentEditorKit = new HTMLEditorKit();
        jContentEditorPane.setEditorKit(contentEditorKit);

        DefaultCaret caret = (DefaultCaret)jContentEditorPane.getCaret();
        caret.setUpdatePolicy(DefaultCaret.NEVER_UPDATE);

        // Apply the styles to both areas.
        StyleSheet contentStyleSheet = contentEditorKit.getStyleSheet();
        StyleSheet headerStyleSheet = headerEditorKit.getStyleSheet();

        try {

            InputStream is = getClass().getResourceAsStream("/resources/help.css");
            Reader r = new BufferedReader(new InputStreamReader(is, "ISO-8859-1"));
            contentStyleSheet.loadRules(r, null);
            headerStyleSheet.loadRules(r, null);
            r.close();
        } catch (IOException e) {
            contentStyleSheet.addRule("body { background: white; color: #404042;}");
            headerStyleSheet.addRule("body { background: white; color: #404042;}");
        }

        Document doc = contentEditorKit.createDefaultDocument();
        jContentEditorPane.setDocument(doc);
        jContentEditorPane.setText(body);

        // Set up the main Popup Frame
        JFrame popupFrame = new JFrame("");
        popupFrame.setUndecorated(true);
        popupFrame.setDefaultCloseOperation(JFrame.DISPOSE_ON_CLOSE);
        popupFrame.setSize(new Dimension(660, 265));

        // Set the location according to the component that called it
        Point location = baseComponent.getLocationOnScreen();
        popupFrame.setLocation(location.x - 500, location.y);
        popupFrame.setVisible(true);

        // Set up the main panel that'll house our components
        JPanel mainPanel = new JPanel(new GridBagLayout());
        mainPanel.setBorder(new EmptyBorder(0, 0, 0, 0));
        popupFrame.getContentPane().add(mainPanel);

        GridBagConstraints gbc = new GridBagConstraints();
        gbc.insets = new Insets(0,0,0,0);
        gbc.gridx = 0;
        gbc.gridy = 0;
        gbc.weightx = 1;
        gbc.weighty = 0;
        gbc.anchor = NORTH;
        gbc.fill = GridBagConstraints.HORIZONTAL;
        jHeaderEditorPane.setText("<h2>" + title + "</h2><hr/>");
        mainPanel.add(jHeaderEditorPane, gbc);

        gbc.gridx=0;
        gbc.gridy=1;
        gbc.weightx = 1;
        gbc.weighty = 1;
        gbc.fill = GridBagConstraints.BOTH;
        Border border = BorderFactory.createEmptyBorder(0, 0, 0, 0);
        contentScrollPane.setBorder(border);

        mainPanel.add(contentScrollPane, gbc);

        popupFrame.addWindowListener(new WindowAdapter() {
            @Override
            public void windowIconified(WindowEvent wEvt) {
                ((JFrame) wEvt.getSource()).dispose();
            }

            @Override
            public void windowDeactivated(WindowEvent wEvt) {
                ((JFrame) wEvt.getSource()).dispose();
            }
        });
    }
}
