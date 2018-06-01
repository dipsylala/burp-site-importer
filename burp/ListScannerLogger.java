package burp;

import javax.swing.*;

class ListScannerLogger implements IListScannerLogger {
    private final JTextArea logger;

    ListScannerLogger(JTextArea logger){

        this.logger = logger;
    }

    public synchronized void log (String message){
        logger.append(message + System.lineSeparator());
    }
    public synchronized void clear () { logger.setText(""); }
}
