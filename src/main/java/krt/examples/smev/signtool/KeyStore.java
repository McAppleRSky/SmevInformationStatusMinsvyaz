package krt.examples.smev.signtool;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

import java.io.IOException;
import java.io.InputStream;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.UnrecoverableKeyException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.Enumeration;

public class KeyStore implements IKeyStore {
    private static final transient Log LOG = LogFactory.getLog(KeyStore.class);

    private java.security.KeyStore keyStore;
    private String storeName;

    public KeyStore(java.security.KeyStore keyStore, String storeName) {
        this.keyStore = keyStore;
        this.storeName = storeName;
    }

    public void load(InputStream stream, char[] password) throws IOException, NoSuchAlgorithmException, CertificateException {
        this.keyStore.load(stream, password);
    }

    public Enumeration<String> aliases() throws KeyStoreException {
        return this.keyStore.aliases();
    }

    public X509Certificate getCertificate(String alias) throws KeyStoreException {
        return (X509Certificate) this.keyStore.getCertificate(alias);
    }

    public PrivateKey getKey(String alias, char[] password) throws KeyStoreException, NoSuchAlgorithmException, UnrecoverableKeyException {
        return (PrivateKey) this.keyStore.getKey(alias, password);
    }

    public KeyPair getKeyPair(String alias, String password) throws Exception {
        this.keyStore.load(null, null);
        Enumeration<String> aliases = this.keyStore.aliases();
        if (aliases.hasMoreElements()) {
            X509Certificate cert = this.getCertificate(alias);
            PrivateKey privateKey = this.getKey(alias, password.toCharArray());
            if (cert != null && privateKey != null) {
                LOG.info("Found certificate for alias: " + alias + ", subjectDn: " + cert.getSubjectDN().toString());
                return new KeyPair(cert, privateKey);
            }
        }

        throw new KeyNotFoundException(this.storeName);
    }
}
