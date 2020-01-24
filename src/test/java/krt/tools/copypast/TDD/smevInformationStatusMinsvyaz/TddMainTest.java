package krt.tools.copypast.TDD.smevInformationStatusMinsvyaz;

import krt.examples.xml.javacourse.xml.XslConverter;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.junit.*;

//@FixMethodOrder(MethodSorters.JVM)
public class TddMainTest {

    private static Logger logger =null;

    @BeforeClass
    public static void setLogger() {
        logger = LogManager.getLogger(TddMainTest.class);
        logger.info("Logger demo after start logging ...");
    }

    @Test
    @Ignore
    public void ExcelTest() {
        XslConverter c = new XslConverter();

        String   xml = "./src/test/resources/recipeXslt/excel.xml"
                ,xsl = "./src/test/resources/recipeXslt/excel.xslt";
        try {
            String result = c.xmlToString(xml, xsl);
            System.out.println(result);
        } catch (Exception e) {
            e.printStackTrace(System.out);
        }
    }

    @Test
    @Ignore
    public void LibreTest() {
        XslConverter c = new XslConverter();

        String   xml = "./src/test/resources/recipeXslt/libre.xml"
                ,xsl = "./src/test/resources/recipeXslt/excel.xslt";
        try {
            String result = c.xmlToString(xml, xsl);
            System.out.println(result);
        } catch (Exception e) {
            e.printStackTrace(System.out);
        }
    }

    @Test
    public void OpenTest() {
        XslConverter c = new XslConverter();

        String   xml = "./src/test/resources/recipeXslt/open.xml"
                ,xsl = "./src/test/resources/recipeXslt/excel.xslt";
        try {
            String result = c.xmlToString(xml, xsl);
            System.out.println(result);
        } catch (Exception e) {
            e.printStackTrace(System.out);
        }
    }

    @Test
    @Ignore
    public void MainTest() //throws IOException
    {
    }

    @AfterClass
    public static void afterMethod(){
    }

}
