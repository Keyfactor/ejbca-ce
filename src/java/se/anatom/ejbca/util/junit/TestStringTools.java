package se.anatom.ejbca.util.junit;

import junit.framework.*;

import org.apache.log4j.Logger;

import se.anatom.ejbca.util.StringTools;


/**
 * Tests the StringTools class .
 *
 * @version $Id: TestStringTools.java,v 1.2 2003-06-26 11:43:25 anatom Exp $
 */
public class TestStringTools extends TestCase {
    private static Logger log = Logger.getLogger(TestStringTools.class);

    /**
     * Creates a new TestStringTools object.
     *
     * @param name name
     */
    public TestStringTools(String name) {
        super(name);
    }

    protected void setUp() throws Exception {
        log.debug(">setUp()");
        log.debug("<setUp()");
    }

    protected void tearDown() throws Exception {
        log.debug(">tearDown()");
        log.debug("<tearDown()");
    }

    /**
     * tests stipping whitespace
     *
     * @throws Exception error
     */
    public void test01StripWhitespace() throws Exception {
        log.debug(">test01StripWhitespace()");

        String test = " foo \t bar \r\n\r\n \f\f\f quu x                  ";
        assertEquals("foobarquux", StringTools.stripWhitespace(test));
        log.debug(">test01StripWhitespace()");
    }
}
