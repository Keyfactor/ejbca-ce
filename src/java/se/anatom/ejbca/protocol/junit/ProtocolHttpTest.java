package se.anatom.ejbca.protocol.junit;

import org.apache.log4j.Logger;

import junit.framework.*;

import com.meterware.httpunit.*;
import com.meterware.pseudoserver.HttpUserAgentTest;

import se.anatom.ejbca.util.CertTools;

/** Tests http pages of ocsp and scep 
 **/
public class ProtocolHttpTest extends TestCase {
    private static Logger log = Logger.getLogger(TestMessages.class);

    private static final String httpReqPath = "http://127.0.0.1:8080/ejbca";
    private static final String resourceOcsp = "publicweb/status/ocsp";
    private static final String resourceScep = "publicweb/apply/scep/pkiclient.exe";
        
    public static void main( String args[] ) {
        junit.textui.TestRunner.run( suite() );
    }


    public static TestSuite suite() {
        return new TestSuite( ProtocolHttpTest.class );
    }


    public ProtocolHttpTest( String name ) {
        super( name );
    }

    protected void setUp() throws Exception {
        log.debug(">setUp()");

        // Install BouncyCastle provider
        CertTools.installBCProvider();

        log.debug("<setUp()");
    }

    protected void tearDown() throws Exception {
    }

    public void testAccess() throws Exception {

        // We want to get error responses without exceptions
        HttpUnitOptions.setExceptionsThrownOnErrorStatus(false);
        WebConversation wc   = new WebConversation();
        
        // Hit ocsp, gives a 500: Internal server error (TODO)
        WebRequest request   = new GetMethodWebRequest( httpReqPath + '/' + resourceOcsp );
        WebResponse response = wc.getResponse( request );
        assertEquals( "Response code", 500, response.getResponseCode() );
        // Hit scep, gives a 400: Bad Request
        request   = new GetMethodWebRequest( httpReqPath + '/' + resourceScep );
        response = wc.getResponse( request );
        assertEquals( "Response code", 400, response.getResponseCode() );
    }


}
