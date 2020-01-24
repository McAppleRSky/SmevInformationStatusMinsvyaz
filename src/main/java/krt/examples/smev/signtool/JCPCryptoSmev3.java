package krt.examples.smev.signtool;

import com.sun.org.apache.xpath.internal.XPathAPI;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.apache.xml.security.Init;
import org.apache.xml.security.exceptions.AlgorithmAlreadyRegisteredException;
import org.apache.xml.security.signature.XMLSignature;
import org.apache.xml.security.transforms.InvalidTransformException;
import org.apache.xml.security.transforms.Transform;
import org.apache.xml.security.transforms.Transforms;
import org.apache.xml.security.utils.XMLUtils;
import org.w3c.dom.*;
import org.w3c.dom.Node;
import ru.CryptoPro.JCPxml.xmldsig.JCPXMLDSigInit;
import krt.examples.smev.transformer.SmevTransformSpi;

import javax.xml.soap.*;
import javax.xml.transform.*;
import javax.xml.transform.dom.DOMResult;
import java.lang.reflect.Field;
import java.security.AccessController;
import java.security.PrivilegedExceptionAction;
import java.security.cert.X509Certificate;
import java.util.Properties;

public class JCPCryptoSmev3 {
    private static final Log LOG = LogFactory.getLog(JCPCryptoSmev3.class);
    private static final String XMLDSIG_MORE_GOSTR34102001_GOSTR3411 = "http://www.w3.org/2001/04/xmldsig-more#gostr34102001-gostr3411";
    private static final String XMLDSIG_MORE_GOSTR3411 = "http://www.w3.org/2001/04/xmldsig-more#gostr3411";
    private static final String GRID = "#";
    private static final String CANONICALIZATION_METHOD = "http://www.w3.org/2001/10/xml-exc-c14n#";
    private static final String SOAP_NS = "http://schemas.xmlsoap.org/soap/envelope/";
    private static final String PREFERRED_PREFIX = "soapenv";

    public JCPCryptoSmev3() {
        LOG.info("Loading key for local operator signature...");
        this.initJCP();
    }

    private void initJCP() {
        System.setProperty("org.apache.xml.security.ignoreLineBreaks", "true");
        if (!Init.isInitialized()) {
            Init.init();
        }

        if (!JCPXMLDSigInit.isInitialized()) {
            JCPXMLDSigInit.init();
            try {
                Transform.register(SmevTransformSpi.ALGORITHM_URN, SmevTransformSpi.class.getName());
                santuarioIgnoreLineBreaks(true);
            } catch (AlgorithmAlreadyRegisteredException | InvalidTransformException | ClassNotFoundException ex) {
                LOG.error(ex.getMessage(), ex);
            }
        }

    }

    public void signXml(byte[] bytes, Properties props) throws Exception {
        long start = System.currentTimeMillis();
        String xmlElementName = "ns2:CallerInformationSystemSignature";
        String xmlElementID = "SIGNED_BY_CALLER";

        KeyPair keyPair = getKeyPair(props);
        X509Certificate cert = keyPair.getCertificate();
        SignatureAlgorithm signatureAlgorithm = SignatureAlgorithm.valueOf(cert.getPublicKey().getAlgorithm());

        SOAPMessage soapMessage = MessageFactory.newInstance().createMessage();
        SOAPEnvelope soapEnvelope = soapMessage.getSOAPPart().getEnvelope();
        Utils.setSOAPEnvelopDefaultPrefix(soapEnvelope);


        Element elementForSign = null;
        Document inputDoc = Utils.buildXmlDocument(bytes);
        String namespaceURI = inputDoc.getNamespaceURI();
        String prefix = inputDoc.getPrefix();
        elementForSign = (Element) this.getElementForSign(inputDoc);
        if (elementForSign == null) {
            elementForSign = inputDoc.getDocumentElement();
        }
        // TODO: Подписать.

        // инициализация объекта формирования ЭЦП
        XMLSignature sig = new XMLSignature(inputDoc, "", signatureAlgorithm.getAlgorithmURI(), CANONICALIZATION_METHOD);

        // добавление в корневой узел XML-документа узла подписи
        if (elementForSign != null) {
            elementForSign.appendChild(sig.getElement());
            if (!elementForSign.hasAttribute("Id")) {
                Attr attr = inputDoc.createAttributeNS(null, "Id");
                attr.setValue(xmlElementID);
                elementForSign.setAttributeNodeNS(attr);
                elementForSign.setIdAttributeNode(attr, true);
            }
        } else {
            throw new SignatureProcessorException("ERROR! Could not find xmlElementName = " + xmlElementName);
        }

        // Определение правил работы с XML-документом и добавление в узел подписи этих правил
        Transforms transforms = new Transforms(inputDoc);
        transforms.addTransform(Transforms.TRANSFORM_ENVELOPED_SIGNATURE);
        transforms.addTransform(Transforms.TRANSFORM_C14N_EXCL_OMIT_COMMENTS);
        transforms.addTransform(SmevTransformSpi.ALGORITHM_URN);

        sig.addDocument(xmlElementID == null ? "" : GRID + xmlElementID, transforms, signatureAlgorithm.getDigestURI());
        sig.addKeyInfo(keyPair.getCertificate());
        sig.sign(keyPair.getPrivateKey());

        long signTime = System.currentTimeMillis() - start;
        LOG.info("Data signed successfully. Time for sign=" + signTime);

//        System.out.println(Utils.element2String(doc.getDocumentElement()));


//        return soapMessage;
    }


    private Node getElementForSign(Document doc) {
        NodeList childNodes = doc.getChildNodes();
        Node node = null;

        int i;
        Node item;
        for (i = 0; i < childNodes.getLength(); ++i) {
            item = childNodes.item(i);
            if ("Envelope".equalsIgnoreCase(item.getLocalName())) {
                node = item;
                break;
            }
        }

        if (node == null) {
            return null;
        } else {
            childNodes = node.getChildNodes();
            node = null;

            for (i = 0; i < childNodes.getLength(); ++i) {
                item = childNodes.item(i);
                if ("Body".equalsIgnoreCase(item.getLocalName())) {
                    node = item;
                    break;
                }
            }

            if (node == null) {
                return null;
            } else {
                childNodes = node.getChildNodes();

                for (i = 0; i < childNodes.getLength(); ++i) {
                    item = childNodes.item(i);
                    if (item.getNodeType() == 1) {
                        return item;
                    }
                }
                return null;
            }
        }
    }


    private boolean hasElement(Document doc, String element) throws TransformerException {
        Node node = XPathAPI.selectSingleNode(doc.getDocumentElement(), element);
        return node != null;
    }

    private void santuarioIgnoreLineBreaks(Boolean mode) {
        try {
            Boolean currMode = mode;
            AccessController.doPrivileged((PrivilegedExceptionAction<Boolean>) () -> {
                Field f = XMLUtils.class.getDeclaredField("ignoreLineBreaks");
                f.setAccessible(true);
                f.set(null, currMode);
                return false;
            });
        } catch (Exception e) {
            LOG.error("santuarioIgnoreLineBreaks " + e.getMessage());
        }
    }

    private KeyPair getKeyPair(Properties props) throws Exception {
        String store = props.getProperty("store");
        IKeyStore keystore = new KeyStore(java.security.KeyStore.getInstance(store, props.getProperty("provider")), store);
        return keystore.getKeyPair(props.getProperty("smev3.alias"), props.getProperty("smev3.pass"));
    }

    private void setDocumentAsSoapMessage(Document doc) {
        Element originalDocumentElement = doc.getDocumentElement();
        Element newDocumentElement = doc.createElementNS(SOAP_NS, originalDocumentElement.getNodeName());
        newDocumentElement.setPrefix(PREFERRED_PREFIX);
        NodeList list = originalDocumentElement.getChildNodes();
        while (list.getLength() != 0) {
            Node item = list.item(0);
            if (item != null) {
//                item.setPrefix(PREFERRED_PREFIX);
                newDocumentElement.appendChild(item);
            }
        }

        doc.replaceChild(newDocumentElement, originalDocumentElement);
    }

    private Document soap2Document(SOAPMessage message) throws SOAPException, TransformerException {
        Transformer transformer = TransformerFactory.newInstance().newTransformer();
        DOMResult result = new DOMResult();
        transformer.transform(message.getSOAPPart().getContent(), result);
        return (Document)result.getNode();
    }


}
