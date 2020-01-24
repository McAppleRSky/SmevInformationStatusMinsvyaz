package krt.examples.smev.signtool;

import java.security.PrivateKey;
import java.security.cert.X509Certificate;

public class KeyPair {

    private X509Certificate certificate;
    private PrivateKey privateKey;

    public KeyPair(X509Certificate certificate, PrivateKey privateKey) {
        this.certificate = certificate;
        this.privateKey = privateKey;
    }

    public X509Certificate getCertificate() {
        return this.certificate;
    }

    public PrivateKey getPrivateKey() {
        return this.privateKey;
    }
}
