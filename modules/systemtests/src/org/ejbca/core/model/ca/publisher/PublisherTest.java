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

import java.security.cert.Certificate;
import java.util.ArrayList;
import java.util.Date;

import junit.framework.TestCase;

import org.apache.log4j.Logger;
import org.ejbca.config.DatabaseConfiguration;
import org.ejbca.config.InternalConfiguration;
import org.ejbca.core.ejb.ca.publisher.PublisherSessionRemote;
import org.ejbca.core.ejb.ca.store.CertificateStoreSessionRemote;
import org.ejbca.core.ejb.config.ConfigurationSessionRemote;
import org.ejbca.core.model.SecConst;
import org.ejbca.core.model.ca.crl.RevokedCertInfo;
import org.ejbca.core.model.ca.store.CertificateInfo;
import org.ejbca.core.model.log.Admin;
import org.ejbca.util.Base64;
import org.ejbca.util.CertTools;
import org.ejbca.util.CryptoProviderTools;
import org.ejbca.util.InterfaceCache;



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

    private static final Admin admin = new Admin(Admin.TYPE_CACOMMANDLINE_USER);
    
    private CertificateStoreSessionRemote certificateStoreSession = InterfaceCache.getCertificateStoreSession();
    private ConfigurationSessionRemote configurationSession = InterfaceCache.getConfigurationSession();
    private PublisherSessionRemote publisherSession = InterfaceCache.getPublisherSession();

    /**
     * Creates a new TestPublisher object.
     *
     * @param name name
     */
    public PublisherTest(String name) {
        super(name);
    }
    
    public void setUp() throws Exception {        
    	CryptoProviderTools.installBCProvider();
    }
    
    public void tearDown() throws Exception {
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
            publisherSession.addPublisher(admin, "TESTLDAP", publisher);
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
            publisherSession.addPublisher(admin, "TESTAD", publisher);
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
            publisherSession.addPublisher(admin, "TESTDUMMYCUSTOM", publisher);
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
        	publisherSession.renamePublisher(admin, "TESTDUMMYCUSTOM", "TESTNEWDUMMYCUSTOM");
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
        publisherSession.clonePublisher(admin, "TESTNEWDUMMYCUSTOM", "TESTCLONEDUMMYCUSTOM");
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
        
        BasePublisher publisher = publisherSession.getPublisher(admin, "TESTCLONEDUMMYCUSTOM");
        publisher.setDescription(publisher.getDescription().toUpperCase());
        publisherSession.changePublisher(admin, "TESTCLONEDUMMYCUSTOM", publisher);
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
        ArrayList<Integer> publishers = new ArrayList<Integer>();
        publishers.add(Integer.valueOf(publisherSession.getPublisherId(admin, "TESTNEWDUMMYCUSTOM")));

        boolean ret = publisherSession.storeCertificate(admin, publishers, cert, "test05", "foo123", null, null, SecConst.CERT_ACTIVE, SecConst.CERTTYPE_ENDENTITY, -1, RevokedCertInfo.NOT_REVOKED, "foo", SecConst.CERTPROFILE_FIXED_ENDUSER, new Date().getTime(), null);
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
        
        ArrayList<Integer> publishers = new ArrayList<Integer>();
        publishers.add(Integer.valueOf(publisherSession.getPublisherId(admin, "TESTNEWDUMMYCUSTOM")));
        boolean ret = publisherSession.storeCRL(admin, publishers, testcrl, null, 1, null);
        assertTrue("Storing CRL to dummy publisher failed", ret);
        
        log.trace("<test08storeCRLToDummy()");
    }
   
    public void test14ExternalOCSPPublisherCustom() throws Exception {
	    log.trace(">test14ExternalOCSPPublisher()");
        boolean ret = false;

        ret = false;
		try {
            CustomPublisherContainer publisher = new CustomPublisherContainer();
            publisher.setClassPath(ValidationAuthorityPublisher.class.getName());
		    // We use the default EjbcaDS datasource here, because it probably exists during our junit test run
			final String jndiPrefix = configurationSession.getProperty(InternalConfiguration.CONFIG_DATASOURCENAMEPREFIX, "");
			final String jndiName = jndiPrefix + configurationSession.getProperty(DatabaseConfiguration.CONFIG_DATASOURCENAME, "EjbcaDS");
            log.debug("jndiPrefix=" + jndiPrefix + " jndiName=" + jndiName);
            publisher.setPropertyData("dataSource " + jndiName);
            publisher.setDescription("Used in Junit Test, Remove this one");
            publisherSession.addPublisher(admin, "TESTEXTOCSP", publisher);
            ret = true;
        } catch (PublisherExistsException pee) {
        	log.error(pee);
        }        
        assertTrue("Creating External OCSP Publisher failed", ret);
        int id = publisherSession.getPublisherId(admin, "TESTEXTOCSP");
        publisherSession.testConnection(admin, id);
        
        Certificate cert = CertTools.getCertfromByteArray(testcert);
        ArrayList<Integer> publishers = new ArrayList<Integer>();
        publishers.add(Integer.valueOf(publisherSession.getPublisherId(admin, "TESTEXTOCSP")));

        ret = publisherSession.storeCertificate(admin, publishers, cert, "test05", "foo123", null, null, SecConst.CERT_ACTIVE, SecConst.CERTTYPE_ENDENTITY, -1, RevokedCertInfo.NOT_REVOKED, "foo", SecConst.CERTPROFILE_FIXED_ENDUSER, new Date().getTime(), null);
        assertTrue("Error storing certificate to external ocsp publisher", ret);

        publisherSession.revokeCertificate(admin, publishers, cert, "test05", null, null, SecConst.CERTTYPE_ENDENTITY, RevokedCertInfo.REVOCATION_REASON_CACOMPROMISE, new Date().getTime(), "foo", SecConst.CERTPROFILE_FIXED_ENDUSER, new Date().getTime());
	    log.trace("<test14ExternalOCSPPublisherCustom()");
    }
    
    public void test15ExternalOCSPPublisher() throws Exception {
	    log.trace(">test15ExternalOCSPPublisher()");
        boolean ret = false;

        ret = false;
		try {
			ValidationAuthorityPublisher publisher = new ValidationAuthorityPublisher();
		    // We use the default EjbcaDS datasource here, because it probably exists during our junit test run
			final String jndiPrefix = configurationSession.getProperty(InternalConfiguration.CONFIG_DATASOURCENAMEPREFIX, "");
			final String jndiName = jndiPrefix + configurationSession.getProperty(DatabaseConfiguration.CONFIG_DATASOURCENAME, "EjbcaDS");
            log.debug("jndiPrefix=" + jndiPrefix + " jndiName=" + jndiName);
            publisher.setDataSource(jndiName);
            publisher.setDescription("Used in Junit Test, Remove this one");
            publisherSession.addPublisher(admin, "TESTEXTOCSP2", publisher);
            ret = true;
        } catch (PublisherExistsException pee) {
        	log.error(pee);
        }        
        assertTrue("Creating External OCSP Publisher failed", ret);
        int id = publisherSession.getPublisherId(admin, "TESTEXTOCSP2");
        publisherSession.testConnection(admin, id);
        
        Certificate cert = CertTools.getCertfromByteArray(testcert);
        ArrayList<Integer> publishers = new ArrayList<Integer>();
        publishers.add(Integer.valueOf(publisherSession.getPublisherId(admin, "TESTEXTOCSP2")));
        
        long date = new Date().getTime();
        ret = publisherSession.storeCertificate(admin, publishers, cert, "test05", "foo123", null, null, SecConst.CERT_ACTIVE, SecConst.CERTTYPE_ENDENTITY, -1, RevokedCertInfo.NOT_REVOKED, "foo", SecConst.CERTPROFILE_FIXED_ENDUSER, date, null);
        assertTrue("Error storing certificate to external ocsp publisher", ret);

        CertificateInfo info = certificateStoreSession.getCertificateInfo(admin, CertTools.getFingerprintAsString(cert));
        assertEquals(SecConst.CERTPROFILE_FIXED_ENDUSER, info.getCertificateProfileId());
        assertEquals("foo", info.getTag());
        assertEquals(date, info.getUpdateTime().getTime());

        date = date + 12345;
        publisherSession.revokeCertificate(admin, publishers, cert, "test05", null, null, SecConst.CERTTYPE_ENDENTITY, RevokedCertInfo.REVOCATION_REASON_CACOMPROMISE, new Date().getTime(), "foobar", 12345, date);

        info = certificateStoreSession.getCertificateInfo(admin, CertTools.getFingerprintAsString(cert));
        assertEquals(12345, info.getCertificateProfileId());
        assertEquals("foobar", info.getTag());
        assertEquals(date, info.getUpdateTime().getTime());

        // Test storing and updating CRLs as well
        publisherSession.storeCRL(admin, publishers, testcrl, "test05", 1, null);
        publisherSession.storeCRL(admin, publishers, testcrl, "test05", 1, null);
        
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
        	publisherSession.removePublisher(admin, "TESTLDAP");            
        } catch (Exception pee) {ret = false;}
        try {
        	publisherSession.removePublisher(admin, "TESTAD");
        } catch (Exception pee) {ret = false;}
        try {
        	publisherSession.removePublisher(admin, "TESTNEWDUMMYCUSTOM");
        } catch (Exception pee) {ret = false;}
        try {
        	publisherSession.removePublisher(admin, "TESTCLONEDUMMYCUSTOM");
        } catch (Exception pee) {ret = false;}
        try {
        	publisherSession.removePublisher(admin, "TESTEXTOCSP");            
        } catch (Exception pee) {ret = false;}
        try {
        	publisherSession.removePublisher(admin, "TESTEXTOCSP2");            
        } catch (Exception pee) {ret = false;}
        assertTrue("Removing Publisher failed", ret);
        
        log.trace("<test99removePublishers()");
    }

} // TestPublisher
