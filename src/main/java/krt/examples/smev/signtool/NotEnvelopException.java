package krt.examples.smev.signtool;

public class NotEnvelopException extends Exception {
    public NotEnvelopException(String arg) {
        super("Document not contains Envelop tag: " + arg);
    }
}
