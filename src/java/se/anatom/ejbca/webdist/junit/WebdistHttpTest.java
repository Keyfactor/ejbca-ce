package se.anatom.ejbca.webdist.junit;

import junit.framework.*;
import com.meterware.httpunit.*;

/** Tests http pages of public webdist
 **/
public class WebdistHttpTest extends TestCase {

    public static void main( String args[] ) {
        junit.textui.TestRunner.run( suite() );
    }


    public static TestSuite suite() {
        return new TestSuite( WebdistHttpTest.class );
    }


    public WebdistHttpTest( String name ) {
        super( name );
    }

    public void testJspCompile() throws Exception {
        // We hit the pages and see that they return a 200 value, so we know they at least compile correctly
        String httpReqPath = "http://127.0.0.1:8080/ejbca";
        String resourceName = "publicweb/webdist";
        String resourceName1 = "publicweb/webdist/cacert.jsp";
        String resourceName2 = "publicweb/webdist/cacrl.jsp";
        String resourceName3 = "publicweb/webdist/revoked.jsp";
        String resourceName4 = "publicweb/webdist/listcerts.jsp";
        String resourceName5 = "publicweb/webdist/certdist.jsp";

        // We want to get a 404 response without exceptions
        HttpUnitOptions.setExceptionsThrownOnErrorStatus(false);
        WebConversation wc   = new WebConversation();
        WebRequest request   = new GetMethodWebRequest( httpReqPath + '/' + resourceName );
        WebResponse response = wc.getResponse( request );
        assertEquals( "Response code", 200, response.getResponseCode() );
        request   = new GetMethodWebRequest( httpReqPath + '/' + resourceName1 );
        response = wc.getResponse( request );
        assertEquals( "Response code", 200, response.getResponseCode() );
        request   = new GetMethodWebRequest( httpReqPath + '/' + resourceName2 );
        response = wc.getResponse( request );
        assertEquals( "Response code", 200, response.getResponseCode() );
        request   = new GetMethodWebRequest( httpReqPath + '/' + resourceName3 );
        response = wc.getResponse( request );
        assertEquals( "Response code", 200, response.getResponseCode() );
        request   = new GetMethodWebRequest( httpReqPath + '/' + resourceName4 );
        response = wc.getResponse( request );
        assertEquals( "Response code", 200, response.getResponseCode() );
        request   = new GetMethodWebRequest( httpReqPath + '/' + resourceName5 );
        response = wc.getResponse( request );
        // Without params this gives a 404 (not found)
        assertEquals( "Response code", 404, response.getResponseCode() );
    }


}
