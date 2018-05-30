package burp;

import javax.swing.*;
import javax.swing.text.DefaultCaret;
import javax.swing.text.Document;
import javax.swing.text.html.HTMLEditorKit;
import javax.swing.text.html.StyleSheet;
import java.awt.*;
import java.awt.event.FocusEvent;
import java.awt.event.FocusListener;
import java.awt.event.WindowEvent;
import java.io.*;

public class PopUpHelp implements FocusListener {

    JFrame popupFrame;

    PopUpHelp(String body, Component baseComponent) {
        JEditorPane jEditorPane = new JEditorPane();
        jEditorPane.setEditable(false);

        JScrollPane scrollPane = new JScrollPane(jEditorPane);
        scrollPane.setAutoscrolls(false);

        HTMLEditorKit kit = new HTMLEditorKit();
        jEditorPane.setEditorKit(kit);

        DefaultCaret caret = (DefaultCaret)jEditorPane.getCaret();
        caret.setUpdatePolicy(DefaultCaret.NEVER_UPDATE);

        // add some styles to the html

        try {
            StyleSheet styleSheet = kit.getStyleSheet();
            InputStream is = getClass().getResourceAsStream("/resources/help.css");
            Reader r = new BufferedReader(new InputStreamReader(is, "ISO-8859-1"));
            styleSheet.loadRules(r, null);
            r.close();
        } catch (IOException e) {

        }

        Document doc = kit.createDefaultDocument();
        jEditorPane.setDocument(doc);
        jEditorPane.setText(body);

        popupFrame = new JFrame("");
        popupFrame.setUndecorated(true);
        popupFrame.getContentPane().add(scrollPane, BorderLayout.CENTER);

        popupFrame.setDefaultCloseOperation(JFrame.DISPOSE_ON_CLOSE);

        popupFrame.setSize(new Dimension(660, 265));

        // Set the location according to the component that called it
        Point location = baseComponent.getLocationOnScreen();
        popupFrame.setLocation(location.x - 500, location.y);
        popupFrame.setVisible(true);

        jEditorPane.addFocusListener(this);
    }

    @Override
    public void focusGained(FocusEvent focusEvent) {

    }

    @Override
    public void focusLost(FocusEvent focusEvent) {
        popupFrame.dispatchEvent(new WindowEvent(popupFrame, WindowEvent.WINDOW_CLOSING));
    }
}
