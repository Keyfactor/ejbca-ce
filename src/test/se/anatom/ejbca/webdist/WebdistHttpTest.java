/*************************************************************************
 *                                                                       *
 *  EJBCA: The OpenSource Certificate Authority                          *
 *                                                                       *
 *  This software is free software; you can redistribute it and/or       *
 *  modify it under the terms of the GNU Lesser General Public           *
 *  License as published by the Free Software Foundation; either         *
 *  version 2.1 of the License, or any later version.                    *
 *                                                                       *
 *  See terms of license at gnu.org.                                     *
 *                                                                       *
 *************************************************************************/
 
package se.anatom.ejbca.webdist;

import junit.framework.TestCase;
import junit.framework.TestSuite;

import com.meterware.httpunit.GetMethodWebRequest;
import com.meterware.httpunit.HttpUnitOptions;
import com.meterware.httpunit.WebConversation;
import com.meterware.httpunit.WebRequest;
import com.meterware.httpunit.WebResponse;

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
        String resourceName = "publicweb/webdist/certdist";
        String resourceName1 = "publicweb/webdist/certdist?cmd=cacert&issuer=CN%3dAdminCA1%2cO%3dEJBCA+TomasLaptop%2cC%3dSE&level=0";

        // We want to get a 404 response without exceptions
        HttpUnitOptions.setExceptionsThrownOnErrorStatus(false);
        WebConversation wc   = new WebConversation();
        WebRequest request   = new GetMethodWebRequest( httpReqPath + '/' + resourceName );
        WebResponse response = wc.getResponse( request );
        assertEquals( "Response code", 400, response.getResponseCode() );
        request   = new GetMethodWebRequest( httpReqPath + '/' + resourceName1 );
        response = wc.getResponse( request );
        assertEquals( "Response code", 200, response.getResponseCode() );
    }

    public void testPublicWeb() throws Exception {
        // We hit the pages and see that they return a 200 value, so we know they at least compile correctly
        String httpReqPath = "http://127.0.0.1:8080/ejbca";
        String resourceName = "retrieve/ca_crls.jsp";
        String resourceName1 = "retrieve/ca_certs.jsp";
        String resourceName2 = "retrieve/latest_cert.jsp";
        String resourceName3 = "retrieve/list_certs.jsp";
        String resourceName4 = "retrieve/check_status.jsp";
        String resourceName5 = "enrol/browser.jsp";
        String resourceName6 = "enrol/server.jsp";
        String resourceName7 = "enrol/keystore.jsp";

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
        assertEquals( "Response code", 200, response.getResponseCode() );
        request   = new GetMethodWebRequest( httpReqPath + '/' + resourceName6 );
        response = wc.getResponse( request );
        assertEquals( "Response code", 200, response.getResponseCode() );
        request   = new GetMethodWebRequest( httpReqPath + '/' + resourceName7 );
        response = wc.getResponse( request );
        assertEquals( "Response code", 200, response.getResponseCode() );
    }

}
