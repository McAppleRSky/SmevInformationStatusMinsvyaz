package krt.examples.smev.signtool;

import com.sun.org.apache.xpath.internal.XPathAPI;
import org.apache.commons.codec.binary.Base64;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.apache.ws.security.message.WSSecHeader;
import org.apache.ws.security.message.token.X509Security;
import org.apache.xml.security.Init;
import org.apache.xml.security.exceptions.AlgorithmAlreadyRegisteredException;
import org.apache.xml.security.transforms.InvalidTransformException;
import org.apache.xml.security.transforms.Transform;
import org.apache.xml.security.transforms.Transforms;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.Node;
import org.w3c.dom.NodeList;

//import org.apache.jcp.xml.dsig.internal.dom.XMLDSigRI;
//import ru.CryptoPro.JCPxml.dsig.internal.dom.XMLDSigRI; нужно заменить но нет в jar крипто
import ru.CryptoPro.JCPxml.dsig.internal.dom.XMLDSigRI;
import ru.CryptoPro.JCPxml.xmldsig.JCPXMLDSigInit;
import krt.examples.smev.transformer.SmevTransformSpi;

import javax.xml.crypto.KeySelector;
import javax.xml.crypto.XMLStructure;
import javax.xml.crypto.dsig.*;
import javax.xml.crypto.dsig.dom.DOMSignContext;
import javax.xml.crypto.dsig.dom.DOMValidateContext;
import javax.xml.crypto.dsig.keyinfo.KeyInfo;
import javax.xml.crypto.dsig.keyinfo.KeyInfoFactory;
import javax.xml.crypto.dsig.keyinfo.X509Data;
import javax.xml.crypto.dsig.spec.C14NMethodParameterSpec;
import javax.xml.soap.*;
import java.io.ByteArrayInputStream;
import java.security.Provider;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Properties;

public class JCPCryptoSmev2 {
    private static final Log LOG = LogFactory.getLog(JCPCryptoSmev2.class);
    private static final String XMLDSIG_MORE_GOSTR34102001_GOSTR3411 = "http://www.w3.org/2001/04/xmldsig-more#gostr34102001-gostr3411";
    private static final String XMLDSIG_MORE_GOSTR3411 = "http://www.w3.org/2001/04/xmldsig-more#gostr3411";
    private static final String PREFERRED_PREFIX = "soapenv";
    private static final String SOAP_NS = "http://schemas.xmlsoap.org/soap/envelope/";
    private static final String WSSE_NS = "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd";
    private static final String WSU_NS = "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd";
    private static final String DS_NS = "http://www.w3.org/2000/09/xmldsig#";
    private static final String ENC_TYPE = "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-soap-message-security-1.0#Base64Binary";
    private static final String VAL_TYPE = "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-x509-token-profile-1.0#X509v3";
    private static final String ACTORS_SMEV = "http://smev.gosuslugi.ru/actors/smev";

    public JCPCryptoSmev2() {
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
            } catch (AlgorithmAlreadyRegisteredException | InvalidTransformException | ClassNotFoundException ex) {
                LOG.error(ex.getMessage(), ex);
            }
        }
    }

    public SOAPMessage sign(byte[] bytes, Properties props) throws Exception {
        long start = System.currentTimeMillis();
        KeyPair keyPair = getKeyPair(props);
        X509Certificate cert = keyPair.getCertificate();
        LOG.debug("Signing OASIS with certificate: " + cert);
        MessageFactory mf = MessageFactory.newInstance();
        SOAPMessage soapMessage = mf.createMessage();
        SOAPPart soapPart = soapMessage.getSOAPPart();
        SOAPEnvelope soapEnvelope = soapPart.getEnvelope();
        Document doc = soapEnvelope.getOwnerDocument();

        soapEnvelope.addNamespaceDeclaration("wsse", WSSE_NS);
        soapEnvelope.addNamespaceDeclaration("wsu", WSU_NS);
        soapEnvelope.addNamespaceDeclaration("ds", DS_NS);
        Utils.setSOAPEnvelopDefaultPrefix(soapEnvelope);
        soapEnvelope.getBody().addAttribute(soapEnvelope.createName("Id", "wsu", WSU_NS), "body");

        // Встраиваемый документ в SOAP контейнер.
        soapEnvelope.getBody().addDocument(Utils.buildXmlDocument(bytes));

        // Добавляем заголовок для помещения информации о подписи:
        WSSecHeader header = new WSSecHeader();
        header.setActor(ACTORS_SMEV);
        header.setMustUnderstand(false);
        header.insertSecurityHeader(doc);

        // Элемент подписи.
        Element token = header.getSecurityHeader();

        // Провайдер
        Provider xmlDSigProvider = new XMLDSigRI();

        // Добавляем описание преобразований над документом и узлом SignedInfo согласно методическим рекомендациям СМЭВ.
        final Transforms transforms = new Transforms(doc);
        transforms.addTransform(Transforms.TRANSFORM_C14N_EXCL_OMIT_COMMENTS);
        XMLSignatureFactory fac = XMLSignatureFactory.getInstance("DOM", xmlDSigProvider);

        // Преобразования над узлом ds:SignedInfo:
        List<javax.xml.crypto.dsig.Transform> transformList = new ArrayList();
        javax.xml.crypto.dsig.Transform transformC14N = fac.newTransform(Transforms.TRANSFORM_C14N_EXCL_OMIT_COMMENTS, (XMLStructure) null);
        transformList.add(transformC14N);

        // Метод получения хэша
        DigestMethod digestMethod = fac.newDigestMethod(XMLDSIG_MORE_GOSTR3411, null);
        // Ссылка на подписываемые данные с алгоритмом хеширования ГОСТ 34.11.
        Reference ref = fac.newReference("#body", digestMethod, transformList, null, null);

        // Задаём алгоритм подписи:
        SignatureMethod signatureMethod = fac.newSignatureMethod(XMLDSIG_MORE_GOSTR34102001_GOSTR3411, null);
        CanonicalizationMethod canonicalizationMethod = fac.newCanonicalizationMethod(CanonicalizationMethod.EXCLUSIVE, (C14NMethodParameterSpec) null);
        SignedInfo si = fac.newSignedInfo(canonicalizationMethod, signatureMethod, Collections.singletonList(ref));

        // Создаём узел ds:KeyInfo с информацией о сертификате:
        KeyInfoFactory kif = fac.getKeyInfoFactory();
        X509Data x509d = kif.newX509Data(Collections.singletonList(cert));
        KeyInfo ki = kif.newKeyInfo(Collections.singletonList(x509d));

        javax.xml.crypto.dsig.XMLSignature sig = fac.newXMLSignature(si, ki);
        DOMSignContext signContext = new DOMSignContext(keyPair.getPrivateKey(), token);
        signContext.setDefaultNamespacePrefix("ds");
        sig.sign(signContext);

        SOAPElement securityElement = (SOAPElement) XPathAPI.selectSingleNode(signContext.getParent(), "//wsse:Security");

        SOAPElement binarySecurityToken = securityElement.addChildElement("BinarySecurityToken", "wsse");
        binarySecurityToken.setAttribute("EncodingType", ENC_TYPE);
        binarySecurityToken.setAttribute("ValueType", VAL_TYPE);
        binarySecurityToken.setAttributeNS(WSU_NS, "wsu:Id", "CertId");
        binarySecurityToken.addTextNode(Base64.encodeBase64String(cert.getEncoded()));

        Element sigE = (Element) XPathAPI.selectSingleNode(signContext.getParent(), "//ds:Signature");

        // Блок данных KeyInfo.
        Node keyE = XPathAPI.selectSingleNode(sigE, "//ds:KeyInfo", sigE);

        // Удаляем содержимое KeyInfo
        keyE.removeChild(XPathAPI.selectSingleNode(keyE, "//ds:X509Data", keyE));
        NodeList chl = keyE.getChildNodes();
        for (int i = 0; i < chl.getLength(); i++) {
            keyE.removeChild(chl.item(i));
        }
        // Узел KeyInfo содержит указание на проверку подписи с помощью сертификата SenderCertificate.
        Node str = keyE.appendChild(doc.createElementNS(WSSE_NS, "wsse:SecurityTokenReference"));
        Element strRef = (Element) str.appendChild(doc.createElementNS(WSSE_NS, "wsse:Reference"));
        strRef.setAttribute("ValueType", VAL_TYPE);
        strRef.setAttribute("URI", "#CertId");
        header.getSecurityHeader().appendChild(sigE);

        long signTime = System.currentTimeMillis() - start;
        LOG.info("Data signed successfully. Time for sign=" + signTime);

        System.out.println(Utils.element2String(doc.getDocumentElement()));
        verifyXml(doc, xmlDSigProvider);

        return soapMessage;
    }

    public void verifyXml(Document doc, Provider xmlDSigProvider) throws Exception {
        // Получение узла, содержащего сертификат.
        final Element wssecontext = doc.createElementNS(null, "namespaceContext");
        wssecontext.setAttributeNS("http://www.w3.org/2000/xmlns/", "xmlns:wsse", WSSE_NS);
        NodeList nodeList = XPathAPI.selectNodeList(doc.getDocumentElement(), "//wsse:Security");
        // Поиск элемента сертификата в блоке BinarySecurityToken.
        Element certElem = null;
        Element elItem = null;
        if (nodeList != null && nodeList.getLength() > 0) {
            String actorAttr = null;
            for (int i = 0; i < nodeList.getLength(); i++) {
                elItem = (Element) nodeList.item(i);
                actorAttr = elItem.getAttributeNS(SOAP_NS, "actor");
                if (actorAttr != null && actorAttr.equals(ACTORS_SMEV)) {
                    certElem = (Element) XPathAPI.selectSingleNode(elItem, "//wsse:BinarySecurityToken[1]", wssecontext);
                    break;
                }
            }
        }
        if (certElem == null) {
            return;
        }
        // Создаем сертификат.
        X509Security x509 = new X509Security(certElem);
        X509Certificate cert = (X509Certificate) CertificateFactory.getInstance("X.509").generateCertificate(new ByteArrayInputStream(x509.getToken()));
        if (cert == null) {
            throw new Exception("Сертификат не найден.");
        }
        LOG.warn("Verify by: " + cert.getSubjectDN());
        // Поиск элемента Signature.
        NodeList nl = doc.getElementsByTagNameNS(DS_NS, "Signature");
        if (nl.getLength() == 0) {
            throw new Exception("Не найден элемент Signature.");
        }
        // Задаем открытый ключ для проверки подписи.
        XMLSignatureFactory fac = XMLSignatureFactory.getInstance("DOM", xmlDSigProvider);
        DOMValidateContext valContext = new DOMValidateContext(KeySelector.singletonKeySelector(cert.getPublicKey()), nl.item(0));
        javax.xml.crypto.dsig.XMLSignature signature = fac.unmarshalXMLSignature(valContext);
        // Проверяем подпись и выводим результат проверки.
        LOG.warn("Verified: " + signature.validate(valContext));
    }


    private KeyPair getKeyPair(Properties props) throws Exception {
        String store = props.getProperty("store");
        IKeyStore keystore = new KeyStore(java.security.KeyStore.getInstance(store, props.getProperty("provider")), store);
        return keystore.getKeyPair(props.getProperty("smev2.alias"), props.getProperty("smev2.pass"));
    }

}
