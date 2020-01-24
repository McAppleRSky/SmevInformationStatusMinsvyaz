package krt.examples.smev.signtool;

import org.apache.commons.io.FilenameUtils;
import org.apache.commons.io.IOUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

import java.io.File;
import java.io.FileInputStream;
import java.io.InputStream;
import java.util.Properties;

public class Application {
    private static final Log log = LogFactory.getLog(Application.class);


    public static void main(String[] args) {
        Properties props = new Properties();

        if (args.length == 0) {
            System.out.println("Укажите путь к XML файлу");
            System.exit(1);
        }

        for (String arg : args) {

            File file = new File(arg);
            String extension = FilenameUtils.getExtension(arg);
            String baseName = FilenameUtils.getBaseName(arg);
            String fullPath = FilenameUtils.getFullPath(arg);

            try {
                props.load(Application.class.getClassLoader().getResourceAsStream("config.properties"));

                InputStream is = new FileInputStream(file);
                byte[] bytes = IOUtils.toByteArray(is);

                if (bytes != null) {
//                    JCPCryptoSmev2 jcpCryptoSmev2 = new JCPCryptoSmev2();
//                    SOAPMessage soapMessage = jcpCryptoSmev2.sign(bytes, props);
//
//                    Utils.outputSoap2File(soapMessage, fullPath + baseName + "-smev2." + extension);

                    // SOAPMessage request = MessageFactory.newInstance().createMessage(null, is);
//                    SOAPMessage responce = Utils.send(soapMessage, props.getProperty("smev2.endpoint"));
//                    Utils.outputSoap2File(responce, fullPath + baseName + "-smev2-resp." + extension);


                    JCPCryptoSmev3 jcpCryptoSmev3 = new JCPCryptoSmev3();
                    jcpCryptoSmev3.signXml(bytes, props);

//                    Utils.outputSoap2File(soapMessage, fullPath + baseName + "-smev3." + extension);



                }
            } catch (Exception e) {
                e.printStackTrace();
            }
        }
    }

}
