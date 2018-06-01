package burp;

import javax.swing.*;
import javax.swing.border.Border;
import javax.swing.plaf.basic.BasicSplitPaneDivider;
import javax.swing.plaf.basic.BasicSplitPaneUI;
import java.awt.*;

class JBurpSplitPane extends JSplitPane {

    JBurpSplitPane(){
        setUI(new BasicSplitPaneUI() {
            public BasicSplitPaneDivider createDefaultDivider() {
                return new BasicSplitPaneDivider(this) {
                    public void setBorder(Border b) {

                    }

                    public void paint(Graphics var1) {
                        var1.setColor(this.getBackground());
                        var1.fillRect(0, 0, this.getWidth(), this.getHeight());
                        if (this.orientation == JSplitPane.VERTICAL_SPLIT) {
                            DrawDownArrow(var1);
                        } else {
                            DrawRightArrow(var1);
                        }
                    }

                    private void DrawRightArrow(Graphics var1) {
                        int[] coordX = new int[3];
                        int[] coordY = new int[3];

                        int minWidth = Math.min(this.getWidth(), 10);
                        int offset = (this.getHeight() / 2) - (minWidth / 2);

                        coordX[0] = 0;
                        coordY[0] = offset;

                        coordX[1] = minWidth;
                        coordY[1] = (minWidth / 2) + offset;

                        coordX[2] = 0;
                        coordY[2] = offset + minWidth;

                        var1.setColor(Constants.BURPSUITE_ORANGE);
                        var1.fillPolygon(coordX, coordY, 3);
                    }

                    private void DrawDownArrow(Graphics var1) {

                        int[] coordX = new int[3];
                        int[] coordY = new int[3];

                        int minHeight = Math.min(this.getHeight(), 10);
                        int offset = (this.getWidth() / 2) - (minHeight / 2);

                        coordX[0] = offset + minHeight;
                        coordY[0] = minHeight;

                        coordX[1] = offset + (minHeight * 2);
                        coordY[1] = 0;

                        coordX[2] = offset;
                        coordY[2] = 0;

                        var1.setColor(Constants.BURPSUITE_ORANGE);
                        var1.fillPolygon(coordX, coordY, 3);
                    }
                };
            }
        });

        setBorder(null);
    }
}
