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

package org.ejbca.core.model.ca.publisher;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.security.cert.Certificate;
import java.util.ArrayList;
import java.util.Date;
import java.util.Properties;

import junit.framework.TestCase;

import org.apache.log4j.Logger;
import org.ejbca.core.model.SecConst;
import org.ejbca.core.model.ca.crl.RevokedCertInfo;
import org.ejbca.core.model.ca.store.CertificateInfo;
import org.ejbca.core.model.log.Admin;
import org.ejbca.util.Base64;
import org.ejbca.util.CertTools;
import org.ejbca.util.TestTools;



/**
 * Tests Publishers.
 *
 * @version $Id$
 */
public class PublisherTest extends TestCase {
    
    static byte[] testcert = Base64.decode(("MIICWzCCAcSgAwIBAgIIJND6Haa3NoAwDQYJKoZIhvcNAQEFBQAwLzEPMA0GA1UE"
            + "AxMGVGVzdENBMQ8wDQYDVQQKEwZBbmFUb20xCzAJBgNVBAYTAlNFMB4XDTAyMDEw"
            + "ODA5MTE1MloXDTA0MDEwODA5MjE1MlowLzEPMA0GA1UEAxMGMjUxMzQ3MQ8wDQYD"
            + "VQQKEwZBbmFUb20xCzAJBgNVBAYTAlNFMIGdMA0GCSqGSIb3DQEBAQUAA4GLADCB"
            + "hwKBgQCQ3UA+nIHECJ79S5VwI8WFLJbAByAnn1k/JEX2/a0nsc2/K3GYzHFItPjy"
            + "Bv5zUccPLbRmkdMlCD1rOcgcR9mmmjMQrbWbWp+iRg0WyCktWb/wUS8uNNuGQYQe"
            + "ACl11SAHFX+u9JUUfSppg7SpqFhSgMlvyU/FiGLVEHDchJEdGQIBEaOBgTB/MA8G"
            + "A1UdEwEB/wQFMAMBAQAwDwYDVR0PAQH/BAUDAwegADAdBgNVHQ4EFgQUyxKILxFM"
            + "MNujjNnbeFpnPgB76UYwHwYDVR0jBBgwFoAUy5k/bKQ6TtpTWhsPWFzafOFgLmsw"
            + "GwYDVR0RBBQwEoEQMjUxMzQ3QGFuYXRvbS5zZTANBgkqhkiG9w0BAQUFAAOBgQAS"
            + "5wSOJhoVJSaEGHMPw6t3e+CbnEL9Yh5GlgxVAJCmIqhoScTMiov3QpDRHOZlZ15c"
            + "UlqugRBtORuA9xnLkrdxYNCHmX6aJTfjdIW61+o/ovP0yz6ulBkqcKzopAZLirX+"
            + "XSWf2uI9miNtxYMVnbQ1KPdEAt7Za3OQR6zcS0lGKg==").getBytes());
    
    static byte[] testcacert = Base64.decode(("MIICLDCCAZWgAwIBAgIISDzEq64yCAcwDQYJKoZIhvcNAQEFBQAwLzEPMA0GA1UE"
            + "AxMGVGVzdENBMQ8wDQYDVQQKEwZBbmFUb20xCzAJBgNVBAYTAlNFMB4XDTAxMTIw"
            + "NDA5MzI1N1oXDTAzMTIwNDA5NDI1N1owLzEPMA0GA1UEAxMGVGVzdENBMQ8wDQYD"
            + "VQQKEwZBbmFUb20xCzAJBgNVBAYTAlNFMIGdMA0GCSqGSIb3DQEBAQUAA4GLADCB"
            + "hwKBgQCnhOvkaj+9Qmt9ZseVn8Jhl6ewTrAOK3c9usxBhiGs+TalGjuAK37bbnbZ"
            + "rlzCZpEsjSZYgXS++3NttiDbPzATkV/c33uIzBHjyk8/paOmTrkIux8hbIYMce+/"
            + "WTYnAM3J41mSuDMy2yZxZ72Yntzqg4UUXiW+JQDkhGx8ZtcSSwIBEaNTMFEwDwYD"
            + "VR0TAQH/BAUwAwEB/zAdBgNVHQ4EFgQUy5k/bKQ6TtpTWhsPWFzafOFgLmswHwYD"
            + "VR0jBBgwFoAUy5k/bKQ6TtpTWhsPWFzafOFgLmswDQYJKoZIhvcNAQEFBQADgYEA"
            + "gHzQLoqLobU43lKvQCiZbYWEXHTf3AdzUd6aMOYOM80iKS9kgrMsnKjp61IFCZwr"
            + "OcY1lOkpjADUTSqfVJWuF1z5k9c1bXnh5zu48LA2r2dlbHqG8twMQ+tPh1MYa3lV"
            + "ugWhKqArGEawICRPUZJrLy/eDbCgVB4QT3rC7rOJOH0=").getBytes());
    
    static byte[] testcrl = Base64.decode(("MIIDEzCCAnwCAQEwDQYJKoZIhvcNAQEFBQAwLzEPMA0GA1UEAxMGVGVzdENBMQ8w"
            + "DQYDVQQKEwZBbmFUb20xCzAJBgNVBAYTAlNFFw0wMjAxMDMxMjExMTFaFw0wMjAx"
            + "MDIxMjExMTFaMIIB5jAZAggfi2rKt4IrZhcNMDIwMTAzMTIxMDUxWjAZAghAxdYk"
            + "7mJxkxcNMDIwMTAzMTIxMDUxWjAZAgg+lCCL+jumXxcNMDIwMTAzMTIxMDUyWjAZ"
            + "Agh4AAPpzSk/+hcNMDIwMTAzMTIxMDUyWjAZAghkhx9SFvxAgxcNMDIwMTAzMTIx"
            + "MDUyWjAZAggj4g5SUqaGvBcNMDIwMTAzMTIxMDUyWjAZAghT+nqB0c6vghcNMDIw"
            + "MTAzMTE1MzMzWjAZAghsBWMAA55+7BcNMDIwMTAzMTE1MzMzWjAZAgg8h0t6rKQY"
            + "ZhcNMDIwMTAzMTE1MzMzWjAZAgh7KFsd40ICwhcNMDIwMTAzMTE1MzM0WjAZAggA"
            + "kFlDNU8ubxcNMDIwMTAzMTE1MzM0WjAZAghyQfo1XNl0EBcNMDIwMTAzMTE1MzM0"
            + "WjAZAggC5Pz7wI/29hcNMDIwMTAyMTY1NDMzWjAZAggEWvzRRpFGoRcNMDIwMTAy"
            + "MTY1NDMzWjAZAggC7Q2W0iXswRcNMDIwMTAyMTY1NDMzWjAZAghrfwG3t6vCiBcN"
            + "MDIwMTAyMTY1NDMzWjAZAgg5C+4zxDGEjhcNMDIwMTAyMTY1NDMzWjAZAggX/olM"
            + "45KxnxcNMDIwMTAyMTY1NDMzWqAvMC0wHwYDVR0jBBgwFoAUy5k/bKQ6TtpTWhsP"
            + "WFzafOFgLmswCgYDVR0UBAMCAQQwDQYJKoZIhvcNAQEFBQADgYEAPvYDZofCOopw"
            + "OCKVGaK1aPpHkJmu5Xi1XtRGO9DhmnSZ28hrNu1A5R8OQI43Z7xFx8YK3S56GRuY"
            + "0EGU/RgM3AWhyTAps66tdyipRavKmH6MMrN4ypW/qbhsd4o8JE9pxxn9zsQaNxYZ"
            + "SNbXM2/YxkdoRSjkrbb9DUdCmCR/kEA=").getBytes());
    
    private static final Logger log = Logger.getLogger(PublisherTest.class);

    private static final Admin admin = new Admin(Admin.TYPE_INTERNALUSER);
    
    private String externalCommand	= "ls";
    private String externalCommand2	= "cmd.exe /c dir";
    private String invalidOption	= " --------------:";
    private String invalidOption2	= " /parameterthatdoesnotexist";

    /**
     * Creates a new TestPublisher object.
     *
     * @param name name
     */
    public PublisherTest(String name) {
        super(name);
    }
    
    protected void setUp() throws Exception {        
        CertTools.installBCProvider();
    }
    
    protected void tearDown() throws Exception {
    }
    
    
    /**
     * adds ldap publisher
     *
     * @throws Exception error
     */
    public void test01AddLDAPPublisher() throws Exception {
        log.trace(">test01AddLDAPPublisher()");
        boolean ret = false;
        try {
            LdapPublisher publisher = new LdapPublisher();
            publisher.setHostnames("localhost");
            publisher.setDescription("Used in Junit Test, Remove this one");
            TestTools.getPublisherSession().addPublisher(admin, "TESTLDAP", publisher);
            ret = true;
        } catch (PublisherExistsException pee) {
        }
        
        assertTrue("Creating LDAP Publisher failed", ret);
        log.trace("<test01AddLDAPPublisher()");
    }
    
    /**
     * adds ad publisher
     *
     * @throws Exception error
     */
    public void test02AddADPublisher() throws Exception {
        log.trace(">test02AddADPublisher() ");
        boolean ret = false;
        try {
            ActiveDirectoryPublisher publisher = new ActiveDirectoryPublisher();
            publisher.setHostnames("localhost");
            publisher.setDescription("Used in Junit Test, Remove this one");
            TestTools.getPublisherSession().addPublisher(admin, "TESTAD", publisher);
            ret = true;
        } catch (PublisherExistsException pee) {
        }
        
        assertTrue("Creating AD Publisher failed", ret);
        log.trace("<test02AddADPublisher() ");
    }
    
    /**
     * adds custom publisher
     *
     * @throws Exception error
     */
    public void test03AddCustomPublisher() throws Exception {
        log.trace(">test03AddCustomPublisher()");
        boolean ret = false;
        try {
            CustomPublisherContainer publisher = new CustomPublisherContainer();
            publisher.setClassPath("org.ejbca.core.model.ca.publisher.DummyCustomPublisher");
            publisher.setDescription("Used in Junit Test, Remove this one");
            TestTools.getPublisherSession().addPublisher(admin, "TESTDUMMYCUSTOM", publisher);
            ret = true;
        } catch (PublisherExistsException pee) {
        }
        
        assertTrue("Creating Custom Publisher failed", ret);
        
        log.trace("<test03AddCustomPublisher()");
    }
    
    /**
     * renames publisher
     *
     * @throws Exception error
     */
    public void test04RenamePublisher() throws Exception {
        log.trace(">test04RenamePublisher()");
        
        boolean ret = false;
        try {
        	TestTools.getPublisherSession().renamePublisher(admin, "TESTDUMMYCUSTOM", "TESTNEWDUMMYCUSTOM");
            ret = true;
        } catch (PublisherExistsException pee) {
        }
        assertTrue("Renaming Custom Publisher failed", ret);
        
        
        log.trace("<test04RenamePublisher()");
    }
    
    /**
     * clones publisher
     *
     * @throws Exception error
     */
    public void test05ClonePublisher() throws Exception {
        log.trace(">test05ClonePublisher()");
        
        boolean ret = false;
        TestTools.getPublisherSession().clonePublisher(admin, "TESTNEWDUMMYCUSTOM", "TESTCLONEDUMMYCUSTOM");
        ret = true;
        assertTrue("Cloning Custom Publisher failed", ret);
        
        log.trace("<test05ClonePublisher()");
    }
    
    
    /**
     * edits publisher
     *
     * @throws Exception error
     */
    public void test06EditPublisher() throws Exception {
        log.trace(">test06EditPublisher()");
        
        boolean ret = false;
        
        BasePublisher publisher = TestTools.getPublisherSession().getPublisher(admin, "TESTCLONEDUMMYCUSTOM");
        publisher.setDescription(publisher.getDescription().toUpperCase());
        TestTools.getPublisherSession().changePublisher(admin, "TESTCLONEDUMMYCUSTOM", publisher);
        ret = true;
        
        assertTrue("Editing Custom Publisher failed", ret);
        
        
        log.trace("<test06EditPublisher()");
    }
    
    /**
     * stores a cert to the dummy publisher
     *
     * @throws Exception error
     */
    public void test07StoreCertToDummy() throws Exception {
        log.trace(">test07StoreCertToDummy()");
        Certificate cert = CertTools.getCertfromByteArray(testcert);
        ArrayList publishers = new ArrayList();
        publishers.add(new Integer(TestTools.getPublisherSession().getPublisherId(admin, "TESTNEWDUMMYCUSTOM")));

        boolean ret = TestTools.getPublisherSession().storeCertificate(new Admin(Admin.TYPE_INTERNALUSER), publishers, cert, "test05", "foo123", null, null, SecConst.CERT_ACTIVE, SecConst.CERTTYPE_ENDENTITY, -1, RevokedCertInfo.NOT_REVOKED, "foo", SecConst.CERTPROFILE_FIXED_ENDUSER, new Date().getTime(), null);
        assertTrue("Storing certificate to dummy publisher failed", ret);
        log.trace("<test07StoreCertToDummyr()");
    }
    
    /**
     * stores a cert to the dummy publisher
     *
     * @throws Exception error
     */
    public void test08storeCRLToDummy() throws Exception {
        log.trace(">test08storeCRLToDummy()");
        
        ArrayList publishers = new ArrayList();
        publishers.add(new Integer(TestTools.getPublisherSession().getPublisherId(admin, "TESTNEWDUMMYCUSTOM")));
        boolean ret = TestTools.getPublisherSession().storeCRL(admin, publishers, testcrl, null, null);
        assertTrue("Storing CRL to dummy publisher failed", ret);
        
        log.trace("<test08storeCRLToDummy()");
    }
    
    
	/**
	 * Test normal operation of GeneralPurposeCustomPublisher.
	 *
	 * @throws Exception error
	 */
	public void test10GenPurpCustPubl() throws Exception {
	    log.trace(">test10GenPurpCustPubl()");
	    
	    GeneralPurposeCustomPublisher gpcPublisher = null;
	    Properties props = new Properties();
	
	    //Make sure an external command exists for testing purposes
	    boolean ret = true;
	    if ( isValidCommand(externalCommand) ) {
	    	ret = false;
	    } else if ( isValidCommand(externalCommand2) ) {
	    	externalCommand = externalCommand2;
	    	invalidOption = invalidOption2;
	    	ret = false; 
	    }
	    assertFalse("This test requires \"" + externalCommand + "\" or \"" + externalCommand2 + "\"to be available.", ret);
	    // Create
    	gpcPublisher = new GeneralPurposeCustomPublisher();
	    // Make sure it fails without a given external command
	    ret = false;
	    try {
	        props.setProperty(GeneralPurposeCustomPublisher.crlExternalCommandPropertyName, "");
	        gpcPublisher.init(props);
			ret = gpcPublisher.storeCRL(admin, testcrl, null);
		} catch (PublisherException e) {
		}
	    assertFalse("Store CRL with GeneralPurposeCustomPublisher did not failed with invalid properties.", ret);
	    // Test function by calling a command that is available on most platforms 
	    ret = false;
	    try {
	        props.setProperty(GeneralPurposeCustomPublisher.crlExternalCommandPropertyName, externalCommand);
	        gpcPublisher.init(props);
			ret = gpcPublisher.storeCRL(admin, testcrl, null);
		} catch (PublisherException e) {
			e.printStackTrace();
		}
	    assertTrue("Store CRL with GeneralPurposeCustomPublisher failed.", ret);
	    log.trace("<test10GenPurpCustPubl()");
	} // test10GenPurpCustPubl

	/**
	 * Verify that GeneralPurposeCustomPublisher will fail on an error code from
	 * an external application. 
	 *
	 * @throws Exception error
	 */
	public void test11GenPurpCustPublErrorCode() throws Exception {
	    log.trace(">test11GenPurpCustPublErrorCode()");
	    
	    GeneralPurposeCustomPublisher gpcPublisher = null;
	    Properties props = new Properties();
	
	    //Make sure an external command exists for testing purposes
	    boolean ret = true;
	    if ( isValidCommand(externalCommand) ) {
	    	ret = false;
	    } else if ( isValidCommand(externalCommand2) ) {
	    	externalCommand = externalCommand2;
	    	invalidOption = invalidOption2;
	    	ret = false; 
	    }
	    assertFalse("This test requires \"" + externalCommand + "\" or \"" + externalCommand2 + "\"to be available.", ret);
	    // Create
    	gpcPublisher = new GeneralPurposeCustomPublisher();
	    // Test function by calling a command that is available on most platforms with invalid option
	    ret = false;
	    try {
	        props.setProperty(GeneralPurposeCustomPublisher.crlExternalCommandPropertyName, externalCommand + invalidOption);
	        props.setProperty(GeneralPurposeCustomPublisher.crlFailOnErrorCodePropertyName, "true");
	        props.setProperty(GeneralPurposeCustomPublisher.crlFailOnStandardErrorPropertyName, "false");
	        gpcPublisher.init(props);
			ret = gpcPublisher.storeCRL(admin, testcrl, null);
		} catch (PublisherException e) {
		}
	    assertFalse("Store CRL with GeneralPurposeCustomPublisher did not fail on errorcode.", ret);
	    ret = false;
	    try {
	        props.setProperty(GeneralPurposeCustomPublisher.certExternalCommandPropertyName, externalCommand + invalidOption);
	        props.setProperty(GeneralPurposeCustomPublisher.certFailOnErrorCodePropertyName, "true");
	        props.setProperty(GeneralPurposeCustomPublisher.certFailOnStandardErrorPropertyName, "false");
	        gpcPublisher.init(props);
			ret = gpcPublisher.storeCRL(admin, testcrl, null);
		} catch (PublisherException e) {
		}
	    assertFalse("Store cert with GeneralPurposeCustomPublisher did not fail on errorcode.", ret);
	    ret = false;
	    try {
	        props.setProperty(GeneralPurposeCustomPublisher.revokeExternalCommandPropertyName, externalCommand + invalidOption);
	        props.setProperty(GeneralPurposeCustomPublisher.revokeFailOnErrorCodePropertyName, "true");
	        props.setProperty(GeneralPurposeCustomPublisher.revokeFailOnStandardErrorPropertyName, "false");
	        gpcPublisher.init(props);
			ret = gpcPublisher.storeCRL(admin, testcrl, null);
		} catch (PublisherException e) {
		}
	    assertFalse("Revoke cert with GeneralPurposeCustomPublisher did not fail on errorcode.", ret);
	    log.trace("<test11GenPurpCustPublErrorCode()");
	} // test11GenPurpCustPublErrorCode
	    
	/**
	 * Verify that GeneralPurposeCustomPublisher will fail on output to standard
	 * error from an external application. 
	 *
	 * @throws Exception error
	 */
	public void test12GenPurpCustPublStandardError() throws Exception {
	    log.trace(">test12GenPurpCustPublStandardError()");
	    
	    GeneralPurposeCustomPublisher gpcPublisher = null;
	    Properties props = new Properties();
	
	    //Make sure an external command exists for testing purposes
	    boolean ret = true;
	    if ( isValidCommand(externalCommand) ) {
	    	ret = false;
	    } else if ( isValidCommand(externalCommand2) ) {
	    	externalCommand = externalCommand2;
	    	invalidOption = invalidOption2;
	    	ret = false; 
	    }
	    assertFalse("This test requires \"" + externalCommand + "\" or \"" + externalCommand2 + "\"to be available.", ret);
	    // Create
    	gpcPublisher = new GeneralPurposeCustomPublisher();
	    // Test function by calling a command that is available on most platforms with invalid option 
	    ret = false;
	    try {
	        props.setProperty(GeneralPurposeCustomPublisher.crlExternalCommandPropertyName, externalCommand + invalidOption);
	        props.setProperty(GeneralPurposeCustomPublisher.crlFailOnErrorCodePropertyName, "false");
	        props.setProperty(GeneralPurposeCustomPublisher.crlFailOnStandardErrorPropertyName, "true");
	        gpcPublisher.init(props);
			ret = gpcPublisher.storeCRL(admin, testcrl, null);
		} catch (PublisherException e) {
		}
	    assertFalse("Store CRL with GeneralPurposeCustomPublisher did not fail on standard error.", ret);
	    ret = false;
	    try {
	        props.setProperty(GeneralPurposeCustomPublisher.certExternalCommandPropertyName, externalCommand + invalidOption);
	        props.setProperty(GeneralPurposeCustomPublisher.certFailOnErrorCodePropertyName, "false");
	        props.setProperty(GeneralPurposeCustomPublisher.certFailOnStandardErrorPropertyName, "true");
	        gpcPublisher.init(props);
			ret = gpcPublisher.storeCRL(admin, testcrl, null);
		} catch (PublisherException e) {
		}
	    assertFalse("Store cert with GeneralPurposeCustomPublisher did not fail on standard error.", ret);
	    ret = false;
	    try {
	        props.setProperty(GeneralPurposeCustomPublisher.revokeExternalCommandPropertyName, externalCommand + invalidOption);
	        props.setProperty(GeneralPurposeCustomPublisher.revokeFailOnErrorCodePropertyName, "false");
	        props.setProperty(GeneralPurposeCustomPublisher.revokeFailOnStandardErrorPropertyName, "true");
	        gpcPublisher.init(props);
			ret = gpcPublisher.storeCRL(admin, testcrl, null);
		} catch (PublisherException e) {
		}
	    assertFalse("Revoke cert with GeneralPurposeCustomPublisher did not fail on standard error.", ret);
	    log.trace("<test12GenPurpCustPublStandardError()");
	} // test12GenPurpCustPublStandardError

	/**
	 * Test that the GeneralPurposeCustomPublisher fails when the external executable file does not exist.
	 *  
	 * @throws Exception
	 */
	public void test13GenPurpCustPublConnection() throws Exception {
	    log.trace(">test13GenPurpCustPublConnection()");
	    GeneralPurposeCustomPublisher gpcPublisher = null;
	    Properties props = new Properties();
	    // Create
    	gpcPublisher = new GeneralPurposeCustomPublisher();
	    // Test connection separatly for all publishers with invalid filename 
	    boolean ret = false;
	    try {
	        props.setProperty(GeneralPurposeCustomPublisher.crlExternalCommandPropertyName, "randomfilenamethatdoesnotexistandneverwill8998752");
	        gpcPublisher.init(props);
			gpcPublisher.testConnection(admin);
			ret = true;
		} catch (PublisherConnectionException e) {
		}
	    assertFalse("testConnection reported all ok, but commandfile does not exist!", ret);
	    ret = false;
	    try {
	        props.setProperty(GeneralPurposeCustomPublisher.certExternalCommandPropertyName, "randomfilenamethatdoesnotexistandneverwill8998752");
	        gpcPublisher.init(props);
			gpcPublisher.testConnection(admin);
			ret = true;
		} catch (PublisherConnectionException e) {
		}
	    assertFalse("testConnection reported all ok, but commandfile does not exist!", ret);
	    ret = false;
	    try {
	        props.setProperty(GeneralPurposeCustomPublisher.revokeExternalCommandPropertyName, "randomfilenamethatdoesnotexistandneverwill8998752");
	        gpcPublisher.init(props);
			gpcPublisher.testConnection(admin);
			ret = true;
		} catch (PublisherConnectionException e) {
		}
	    assertFalse("testConnection reported all ok, but commandfile does not exist!", ret);
	    log.trace("<test13GenPurpCustPublStandardError()");
	} // test13GenPurpCustPublConnection

    public void test14ExternalOCSPPublisherCustom() throws Exception {
	    log.trace(">test14ExternalOCSPPublisher()");
        boolean ret = false;

        ret = false;
		try {
            CustomPublisherContainer publisher = new CustomPublisherContainer();
            publisher.setClassPath(ExternalOCSPPublisher.class.getName());
		    // We use the default EjbcaDS datasource here, because it probably exists during our junit test run
            publisher.setPropertyData("dataSource java:/EjbcaDS");
            publisher.setDescription("Used in Junit Test, Remove this one");
            TestTools.getPublisherSession().addPublisher(admin, "TESTEXTOCSP", publisher);
            ret = true;
        } catch (PublisherExistsException pee) {
        	log.error(pee);
        }        
        assertTrue("Creating External OCSP Publisher failed", ret);
        int id = TestTools.getPublisherSession().getPublisherId(admin, "TESTEXTOCSP");
        TestTools.getPublisherSession().testConnection(admin, id);
        
        Certificate cert = CertTools.getCertfromByteArray(testcert);
        ArrayList publishers = new ArrayList();
        publishers.add(new Integer(TestTools.getPublisherSession().getPublisherId(admin, "TESTEXTOCSP")));

        ret = TestTools.getPublisherSession().storeCertificate(new Admin(Admin.TYPE_INTERNALUSER), publishers, cert, "test05", "foo123", null, null, SecConst.CERT_ACTIVE, SecConst.CERTTYPE_ENDENTITY, -1, RevokedCertInfo.NOT_REVOKED, "foo", SecConst.CERTPROFILE_FIXED_ENDUSER, new Date().getTime(), null);
        assertTrue("Error storing certificate to external ocsp publisher", ret);

        TestTools.getPublisherSession().revokeCertificate(new Admin(Admin.TYPE_INTERNALUSER), publishers, cert, "test05", null, null, SecConst.CERTTYPE_ENDENTITY, RevokedCertInfo.REVOKATION_REASON_CACOMPROMISE, new Date().getTime(), "foo", SecConst.CERTPROFILE_FIXED_ENDUSER, new Date().getTime());
	    log.trace("<test14ExternalOCSPPublisherCustom()");
    }
    
    public void test15ExternalOCSPPublisher() throws Exception {
	    log.trace(">test15ExternalOCSPPublisher()");
        boolean ret = false;

        ret = false;
		try {
			ExternalOCSPPublisher publisher = new ExternalOCSPPublisher();
		    // We use the default EjbcaDS datasource here, because it probably exists during our junit test run
            publisher.setDataSource("java:/EjbcaDS");
            publisher.setDescription("Used in Junit Test, Remove this one");
            TestTools.getPublisherSession().addPublisher(admin, "TESTEXTOCSP2", publisher);
            ret = true;
        } catch (PublisherExistsException pee) {
        	log.error(pee);
        }        
        assertTrue("Creating External OCSP Publisher failed", ret);
        int id = TestTools.getPublisherSession().getPublisherId(admin, "TESTEXTOCSP2");
        TestTools.getPublisherSession().testConnection(admin, id);
        
        Certificate cert = CertTools.getCertfromByteArray(testcert);
        ArrayList publishers = new ArrayList();
        publishers.add(new Integer(TestTools.getPublisherSession().getPublisherId(admin, "TESTEXTOCSP2")));
        
        long date = new Date().getTime();
        ret = TestTools.getPublisherSession().storeCertificate(new Admin(Admin.TYPE_INTERNALUSER), publishers, cert, "test05", "foo123", null, null, SecConst.CERT_ACTIVE, SecConst.CERTTYPE_ENDENTITY, -1, RevokedCertInfo.NOT_REVOKED, "foo", SecConst.CERTPROFILE_FIXED_ENDUSER, date, null);
        assertTrue("Error storing certificate to external ocsp publisher", ret);

        CertificateInfo info = TestTools.getCertificateStoreSession().getCertificateInfo(admin, CertTools.getFingerprintAsString(cert));
        assertEquals(SecConst.CERTPROFILE_FIXED_ENDUSER, info.getCertificateProfileId());
        assertEquals("foo", info.getTag());
        assertEquals(date, info.getUpdateTime().getTime());

        date = date + 12345;
        TestTools.getPublisherSession().revokeCertificate(new Admin(Admin.TYPE_INTERNALUSER), publishers, cert, "test05", null, null, SecConst.CERTTYPE_ENDENTITY, RevokedCertInfo.REVOKATION_REASON_CACOMPROMISE, new Date().getTime(), "foobar", 12345, date);

        info = TestTools.getCertificateStoreSession().getCertificateInfo(admin, CertTools.getFingerprintAsString(cert));
        assertEquals(12345, info.getCertificateProfileId());
        assertEquals("foobar", info.getTag());
        assertEquals(date, info.getUpdateTime().getTime());

        log.trace("<test15ExternalOCSPPublisher()");
    }

    /**
     * removes all publishers
     *
     * @throws Exception error
     */
    public void test99removePublishers() throws Exception {
        log.trace(">test99removePublishers()");
        boolean ret = true;
        try {
        	TestTools.getPublisherSession().removePublisher(admin, "TESTLDAP");            
        } catch (Exception pee) {ret = false;}
        try {
        	TestTools.getPublisherSession().removePublisher(admin, "TESTAD");
        } catch (Exception pee) {ret = false;}
        try {
        	TestTools.getPublisherSession().removePublisher(admin, "TESTNEWDUMMYCUSTOM");
        } catch (Exception pee) {ret = false;}
        try {
        	TestTools.getPublisherSession().removePublisher(admin, "TESTCLONEDUMMYCUSTOM");
        } catch (Exception pee) {ret = false;}
        try {
        	TestTools.getPublisherSession().removePublisher(admin, "TESTEXTOCSP");            
        } catch (Exception pee) {ret = false;}
        try {
        	TestTools.getPublisherSession().removePublisher(admin, "TESTEXTOCSP2");            
        } catch (Exception pee) {ret = false;}
        assertTrue("Removing Publisher failed", ret);
        
        log.trace("<test99removePublishers()");
    }


	/**
	 * Tries to execute the argument and return true if no exception was thrown and the command returned 0.
	 * 
	 * @param externalCommandToTest The String to run.
	 * @return Returns false on error.
	 */
	private boolean isValidCommand(String externalCommandToTest) {
	    boolean ret = false;
		try {
			String[] cmdarray = externalCommandToTest.split("\\s");
			Process externalProcess = Runtime.getRuntime().exec( cmdarray, null, null );
			BufferedReader br = new BufferedReader( new InputStreamReader( externalProcess.getInputStream() ) );
			while (br.readLine() != null) { }
			if ( externalProcess.waitFor() == 0 ) {
				ret = true;
			}
		} catch (IOException e) {
		} catch (InterruptedException e) {
		}
		return ret;
	} // isValidCommand
} // TestPublisher
