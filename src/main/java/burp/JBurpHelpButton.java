package burp;

import javax.imageio.ImageIO;
import javax.swing.*;
import java.awt.*;
import java.io.IOException;
import java.io.InputStream;

class JBurpHelpButton extends JButton {

    JBurpHelpButton(){
        setFocusPainted(false);
        setPreferredSize(new Dimension(30, 30));
        InputStream is = getClass().getResourceAsStream("/main/resources/question_mark.png");

        try {
            Image image = ImageIO.read(is);
            Image resizedImage = image.getScaledInstance(14, 18,Image.SCALE_SMOOTH );
            setIcon(new ImageIcon(resizedImage));
        } catch (IOException e) {
            setText("?");
        }
    }
}
