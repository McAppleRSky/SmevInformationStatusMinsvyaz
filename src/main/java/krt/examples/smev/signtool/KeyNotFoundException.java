package krt.examples.smev.signtool;

public class KeyNotFoundException extends Exception {
    public KeyNotFoundException(String store) {
        super("Failed to fetch key from store: " + store);
    }
}
