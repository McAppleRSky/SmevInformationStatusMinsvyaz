package krt.examples.smev.signtool;

public enum SignatureAlgorithm {
    GOST3410EL("1.2.643.2.2.19", "GOST3411withGOST3410EL", "1.2.643.2.2.9", "GOST3411", "http://www.w3.org/2001/04/xmldsig-more#gostr34102001-gostr3411", "http://www.w3.org/2001/04/xmldsig-more#gostr3411"),
    GOST3410_2012_256("1.2.643.7.1.1.1.1", "GOST3411_2012_256withGOST3410DH_2012_256", "1.2.643.7.1.1.2.2", "GOST3411_2012_256", "urn:ietf:params:xml:ns:cpxmlsec:algorithms:gostr34102012-gostr34112012-256", "urn:ietf:params:xml:ns:cpxmlsec:algorithms:gostr34112012-256"),
    GOST3410_2012_512("1.2.643.7.1.1.1.2", "GOST3411_2012_512withGOST3410DH_2012_512", "1.2.643.7.1.1.2.3", "GOST3411_2012_512", "urn:ietf:params:xml:ns:cpxmlsec:algorithms:gostr34102012-gostr34112012-512", "urn:ietf:params:xml:ns:cpxmlsec:algorithms:gostr34112012-512");

    private String algorithmOID;
    private String algorithm;
    private String digestOID;
    private String digestAlgorithm;
    private String algorithmURI;
    private String digestURI;

    private SignatureAlgorithm(String algorithmOID, String gostElSignName, String digestOID, String digestAlgorithm, String algorithmURI, String digestURI) {
        this.algorithmOID = algorithmOID;
        this.algorithm = gostElSignName;
        this.digestOID = digestOID;
        this.digestAlgorithm = digestAlgorithm;
        this.algorithmURI = algorithmURI;
        this.digestURI = digestURI;
    }

    public String getAlgorithm() {
        return this.algorithm;
    }

    public String getDigestOID() {
        return this.digestOID;
    }

    public String getAlgorithmOID() {
        return this.algorithmOID;
    }

    public String getDigestAlgorithm() {
        return this.digestAlgorithm;
    }

    public String getAlgorithmURI() {
        return this.algorithmURI;
    }

    public String getDigestURI() {
        return this.digestURI;
    }
}
