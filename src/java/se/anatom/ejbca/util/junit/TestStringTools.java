package se.anatom.ejbca.util.junit;

import org.apache.log4j.Logger;

import junit.framework.*;

import se.anatom.ejbca.util.StringTools;


/**
 * Tests the StringTools class .
 *
 * @version $Id: TestStringTools.java,v 1.3 2003-07-24 08:43:32 anatom Exp $
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
