package krt.examples.smev.signtool;

import java.io.IOException;
import java.io.InputStream;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.UnrecoverableKeyException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.Enumeration;

public interface IKeyStore {
    void load(InputStream stream, char[] password) throws IOException, NoSuchAlgorithmException, CertificateException;

    Enumeration<String> aliases() throws KeyStoreException;

    X509Certificate getCertificate(String alias) throws KeyStoreException;

    PrivateKey getKey(String alias, char[] password) throws KeyStoreException, NoSuchAlgorithmException, UnrecoverableKeyException;

    KeyPair getKeyPair(String alias, String password) throws Exception;
}

