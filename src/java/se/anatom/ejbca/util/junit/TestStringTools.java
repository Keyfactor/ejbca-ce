package se.anatom.ejbca.util.junit;

import se.anatom.ejbca.util.StringTools;

import org.apache.log4j.Logger;
import junit.framework.*;

/**
 * Tests the StringTools class .
 *
 * @version $Id: TestStringTools.java,v 1.1 2003-04-01 11:19:16 scop Exp $
 */
public class TestStringTools extends TestCase
{

  private static Logger log = Logger.getLogger(TestStringTools.class);

  public TestStringTools(String name) {
    super(name);
  }

  protected void setUp()
    throws Exception
  {
    log.debug(">setUp()");
    log.debug("<setUp()");
  }

  protected void tearDown()
    throws Exception
  {
    log.debug(">tearDown()");
    log.debug("<tearDown()");
  }

  
  public void test01StripWhitespace()
    throws Exception
  {
    log.debug(">test01StripWhitespace()");
    String test = " foo \t bar \r\n\r\n \f\f\f quu x                  ";
    assertEquals("foobarquux", StringTools.stripWhitespace(test));
    log.debug(">test01StripWhitespace()");
  }
}
