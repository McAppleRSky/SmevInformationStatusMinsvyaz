package krt.examples.smev.signtool;

import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.xml.sax.SAXException;

import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.parsers.ParserConfigurationException;
import javax.xml.soap.*;
import javax.xml.transform.Transformer;
import javax.xml.transform.TransformerException;
import javax.xml.transform.TransformerFactory;
import javax.xml.transform.dom.DOMSource;
import javax.xml.transform.stream.StreamResult;
import java.io.*;

public class Utils {
    private static final String SOAP_NS = "http://schemas.xmlsoap.org/soap/envelope/";
    private static final String PREFERRED_PREFIX = "soapenv";

    public static String element2String(Element node) throws Exception {
        TransformerFactory tf = TransformerFactory.newInstance();
        Transformer transformer = tf.newTransformer();
        StringWriter writer = new StringWriter();
        transformer.transform(new DOMSource(node), new StreamResult(writer));
        return writer.getBuffer().toString();
    }

    public static String soapMessage2String(SOAPMessage message) throws IOException, SOAPException {
        ByteArrayOutputStream stream = new ByteArrayOutputStream();
        message.writeTo(stream);
        return new String(stream.toByteArray(), "utf-8");
    }

    public static Document buildXmlDocument(byte[] bytes) throws ParserConfigurationException, IOException, SAXException {
        DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
        dbf.setIgnoringElementContentWhitespace(true);
        dbf.setCoalescing(true);
        dbf.setNamespaceAware(true);
        DocumentBuilder db = dbf.newDocumentBuilder();
        Document doc = db.parse(new ByteArrayInputStream(bytes));

        return doc;
    }

    public static void outputXml2File(Document xmlDocument, String fileName) throws IOException, TransformerException {
        TransformerFactory tf = TransformerFactory.newInstance();
        Transformer transformer = tf.newTransformer();

        FileOutputStream os = new FileOutputStream(new File(fileName));
        transformer.transform(new DOMSource(xmlDocument), new StreamResult(os));

    }

    public static void outputSoap2File(SOAPMessage soapMessage, String fileName) throws IOException, SOAPException {
        File outputFile = new File(fileName);
        java.io.FileOutputStream fos = new java.io.FileOutputStream(outputFile);
        soapMessage.writeTo(fos);
        fos.close();

    }

    public static SOAPMessage send(SOAPMessage soapMessage, String url) throws SOAPException {
        SOAPConnectionFactory soapConnectionFactory = SOAPConnectionFactory.newInstance();
        SOAPConnection soapConnection = soapConnectionFactory.createConnection();
        SOAPMessage resp = soapConnection.call(soapMessage, url);

        return resp;
    }

    public static void setSOAPEnvelopDefaultPrefix(SOAPEnvelope soapEnvelope) throws SOAPException {
        soapEnvelope.removeNamespaceDeclaration(soapEnvelope.getPrefix());
        soapEnvelope.addNamespaceDeclaration(PREFERRED_PREFIX, SOAP_NS);
        soapEnvelope.setPrefix(PREFERRED_PREFIX);
        soapEnvelope.getHeader().setPrefix(PREFERRED_PREFIX);
        soapEnvelope.getBody().setPrefix(PREFERRED_PREFIX);
    }

}
