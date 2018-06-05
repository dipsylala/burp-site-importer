package burp;

import javax.swing.*;
import javax.swing.text.Document;
import java.awt.*;

class JBurpPlaceholderTextField extends JTextField {

    private String placeholder;

    JBurpPlaceholderTextField(){}

    JBurpPlaceholderTextField(
            final Document pDoc,
            final String pText,
            final int pColumns)
    {
        super(pDoc, pText, pColumns);
    }

    JBurpPlaceholderTextField(final int pColumns) {
        super(pColumns);
    }

    JBurpPlaceholderTextField(final String pText) {
        super(pText);
    }

    JBurpPlaceholderTextField(final String pText, final int pColumns) {
        super(pText, pColumns);
    }

    String getPlaceholder() {
        return this.placeholder;
    }

    @Override
    protected void paintComponent(final Graphics pG) {
        super.paintComponent(pG);

        if (this.placeholder.length() == 0 || getText().length() > 0) {
            return;
        }

        final Graphics2D g = (Graphics2D) pG;
        g.setRenderingHint( RenderingHints.KEY_ANTIALIASING, RenderingHints.VALUE_ANTIALIAS_ON);
        g.setColor(getDisabledTextColor());
        g.setFont(g.getFont().deriveFont(Font.ITALIC));
        g.drawString(this.placeholder, getInsets().left, pG.getFontMetrics().getMaxAscent() + getInsets().top);
    }

    void setPlaceholder(final String placeholder) {
        this.placeholder = placeholder;
    }
}
