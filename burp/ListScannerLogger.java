package burp;

import javax.swing.*;

class ListScannerLogger implements IListScannerLogger {
    private JTextArea logger;

    public ListScannerLogger(JTextArea logger){

        this.logger = logger;
    }

    public synchronized void Log (String message){
        logger.append(message + System.lineSeparator());
    }
}
