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

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;

import java.security.Principal;
import java.security.cert.Certificate;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Date;
import java.util.HashSet;
import java.util.Set;

import javax.security.auth.x500.X500Principal;

import org.apache.log4j.Logger;
import org.cesecore.authentication.tokens.AuthenticationSubject;
import org.cesecore.authentication.tokens.AuthenticationToken;
import org.cesecore.authentication.tokens.UsernamePrincipal;
import org.cesecore.authorization.control.StandardRules;
import org.cesecore.authorization.rules.AccessRuleData;
import org.cesecore.authorization.rules.AccessRuleState;
import org.cesecore.authorization.user.AccessMatchType;
import org.cesecore.authorization.user.AccessUserAspectData;
import org.cesecore.authorization.user.matchvalues.X500PrincipalAccessMatchValue;
import org.cesecore.certificates.certificate.CertificateInfo;
import org.cesecore.certificates.certificate.CertificateStoreSessionRemote;
import org.cesecore.certificates.crl.RevokedCertInfo;
import org.cesecore.jndi.JndiHelper;
import org.cesecore.mock.authentication.SimpleAuthenticationProviderRemote;
import org.cesecore.mock.authentication.tokens.TestAlwaysAllowLocalAuthenticationToken;
import org.cesecore.roles.RoleData;
import org.cesecore.roles.management.RoleManagementSessionRemote;
import org.cesecore.util.Base64;
import org.cesecore.util.CertTools;
import org.cesecore.util.CryptoProviderTools;
import org.ejbca.config.DatabaseConfiguration;
import org.ejbca.config.InternalConfiguration;
import org.ejbca.core.ejb.ca.publisher.PublisherProxySessionRemote;
import org.ejbca.core.ejb.ca.publisher.PublisherSessionRemote;
import org.ejbca.core.ejb.config.ConfigurationSessionRemote;
import org.ejbca.core.model.SecConst;
import org.ejbca.util.InterfaceCache;
import org.junit.After;
import org.junit.Before;
import org.junit.BeforeClass;
import org.junit.Test;



/**
 * Tests Publishers.
 *
 * @version $Id$
 */
public class PublisherTest {
    
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

    private static final AuthenticationToken internalAdmin = new TestAlwaysAllowLocalAuthenticationToken(new UsernamePrincipal("PublisherTest"));
    
    private final String commonname = this.getClass().getCanonicalName();
    
    private CertificateStoreSessionRemote certificateStoreSession = InterfaceCache.getCertificateStoreSession();
    private ConfigurationSessionRemote configurationSession = JndiHelper.getRemoteSession(ConfigurationSessionRemote.class);
    private PublisherSessionRemote publisherSession = JndiHelper.getRemoteSession(PublisherSessionRemote.class);
    private PublisherProxySessionRemote publisherProxySession = JndiHelper.getRemoteSession(PublisherProxySessionRemote.class);
    
    private RoleManagementSessionRemote roleManagementSession = JndiHelper.getRemoteSession(RoleManagementSessionRemote.class);
    
    private SimpleAuthenticationProviderRemote simpleAuthenticationProvider = JndiHelper.getRemoteSession(SimpleAuthenticationProviderRemote.class);

    private AuthenticationToken admin;
    
    @BeforeClass
    public static void beforeClass() throws Exception {
        CryptoProviderTools.installBCProvider();
    }
    
    @Before
    public void setUp() throws Exception {       
        Certificate cert = CertTools.getCertfromByteArray(testcert);
        int caid = CertTools.getIssuerDN(cert).hashCode();
        String subjectDn = CertTools.getSubjectDN(cert);
        String cN = CertTools.getPartsFromDN(subjectDn, "CN").get(0);  
        
        Set<Principal> principals = new HashSet<Principal>();
        Set<Certificate> credentials = new HashSet<Certificate>();
        credentials.add(cert);
        X500Principal p = new X500Principal(subjectDn);
        principals.add(p);
        AuthenticationSubject subject = new AuthenticationSubject(principals, credentials);
    	admin = simpleAuthenticationProvider.authenticate(subject);
    	
    	RoleData role = roleManagementSession.create(internalAdmin, commonname);   
    	Collection<AccessRuleData> rules = new ArrayList<AccessRuleData>();
    	rules.add(new AccessRuleData(commonname, StandardRules.CAACCESS.resource() + caid, AccessRuleState.RULE_ACCEPT, false));
    	role = roleManagementSession.addAccessRulesToRole(internalAdmin, role, rules);
    	Collection<AccessUserAspectData> users = new ArrayList<AccessUserAspectData>();
    	users.add(new AccessUserAspectData(commonname, caid, X500PrincipalAccessMatchValue.WITH_COMMONNAME, AccessMatchType.TYPE_EQUALCASE, cN));
    	role = roleManagementSession.addSubjectsToRole(internalAdmin, role, users);
    }
    
    @After
    public void tearDown() throws Exception {
        roleManagementSession.remove(internalAdmin, commonname);
    }
    
    
    /**
     * adds ldap publisher
     *
     * @throws Exception error
     */
    @Test
    public void test01AddLDAPPublisher() throws Exception {
        log.trace(">test01AddLDAPPublisher()");
        boolean ret = false;
        try {
            LdapPublisher publisher = new LdapPublisher();
            publisher.setHostnames("localhost");
            publisher.setDescription("Used in Junit Test, Remove this one");
            publisherProxySession.addPublisher(internalAdmin, "TESTLDAP", publisher);
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
    @Test
    public void test02AddADPublisher() throws Exception {
        log.trace(">test02AddADPublisher() ");
        boolean ret = false;
        try {
            ActiveDirectoryPublisher publisher = new ActiveDirectoryPublisher();
            publisher.setHostnames("localhost");
            publisher.setDescription("Used in Junit Test, Remove this one");
            publisherProxySession.addPublisher(internalAdmin, "TESTAD", publisher);
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
    @Test
    public void test03AddCustomPublisher() throws Exception {
        log.trace(">test03AddCustomPublisher()");
        boolean ret = false;
        try {
            CustomPublisherContainer publisher = new CustomPublisherContainer();
            publisher.setClassPath("org.ejbca.core.model.ca.publisher.DummyCustomPublisher");
            publisher.setDescription("Used in Junit Test, Remove this one");
            publisherProxySession.addPublisher(internalAdmin, "TESTDUMMYCUSTOM", publisher);
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
    @Test
    public void test04RenamePublisher() throws Exception {
        log.trace(">test04RenamePublisher()");
        
        boolean ret = false;
        try {
        	publisherProxySession.renamePublisher(internalAdmin, "TESTDUMMYCUSTOM", "TESTNEWDUMMYCUSTOM");
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
    @Test
    public void test05ClonePublisher() throws Exception {
        log.trace(">test05ClonePublisher()");
        
        boolean ret = false;
        publisherProxySession.clonePublisher(internalAdmin, "TESTNEWDUMMYCUSTOM", "TESTCLONEDUMMYCUSTOM");
        ret = true;
        assertTrue("Cloning Custom Publisher failed", ret);
        
        log.trace("<test05ClonePublisher()");
    }
    
    
    /**
     * edits publisher
     *
     * @throws Exception error
     */
    @Test
    public void test06EditPublisher() throws Exception {
        log.trace(">test06EditPublisher()");
        
        boolean ret = false;
        
        BasePublisher publisher = publisherSession.getPublisher("TESTCLONEDUMMYCUSTOM");
        publisher.setDescription(publisher.getDescription().toUpperCase());
        publisherSession.changePublisher(internalAdmin, "TESTCLONEDUMMYCUSTOM", publisher);
        ret = true;
        
        assertTrue("Editing Custom Publisher failed", ret);
        
        
        log.trace("<test06EditPublisher()");
    }
    
    /**
     * stores a cert to the dummy publisher
     *
     * @throws Exception error
     */
    @Test
   public void test07StoreCertToDummy() throws Exception {
        log.trace(">test07StoreCertToDummy()");
        Certificate cert = CertTools.getCertfromByteArray(testcert);
        ArrayList<Integer> publishers = new ArrayList<Integer>();
        publishers.add(Integer.valueOf(publisherProxySession.getPublisherId("TESTNEWDUMMYCUSTOM")));

        boolean ret = publisherSession.storeCertificate(admin, publishers, cert, "test05", "foo123", null, null, SecConst.CERT_ACTIVE, SecConst.CERTTYPE_ENDENTITY, -1, RevokedCertInfo.NOT_REVOKED, "foo", SecConst.CERTPROFILE_FIXED_ENDUSER, new Date().getTime(), null);
        assertTrue("Storing certificate to dummy publisher failed", ret);
        log.trace("<test07StoreCertToDummyr()");
    }
    
    /**
     * stores a cert to the dummy publisher
     *
     * @throws Exception error
     */
    @Test
    public void test08storeCRLToDummy() throws Exception {
        log.trace(">test08storeCRLToDummy()");
       String issuerDn = CertTools.getIssuerDN(CertTools.getCRLfromByteArray(testcrl));
        ArrayList<Integer> publishers = new ArrayList<Integer>();
        publishers.add(Integer.valueOf(publisherProxySession.getPublisherId("TESTNEWDUMMYCUSTOM")));
        boolean ret = publisherSession.storeCRL(admin, publishers, testcrl, null, 1, issuerDn);
        assertTrue("Storing CRL to dummy publisher failed", ret);
        
        log.trace("<test08storeCRLToDummy()");
    }
   
    @Test
    public void test14ExternalOCSPPublisherCustom() throws Exception {
	    log.trace(">test14ExternalOCSPPublisher()");
        boolean ret = false;

        ret = false;
		try {
            CustomPublisherContainer publisher = new CustomPublisherContainer();
            publisher.setClassPath(ValidationAuthorityPublisher.class.getName());
		    // We use the default EjbcaDS datasource here, because it probably exists during our junit test run
			final String jndiPrefix = configurationSession.getProperty(InternalConfiguration.CONFIG_DATASOURCENAMEPREFIX);
			final String jndiName = jndiPrefix + configurationSession.getProperty(DatabaseConfiguration.CONFIG_DATASOURCENAME);
            log.debug("jndiPrefix=" + jndiPrefix + " jndiName=" + jndiName);
            publisher.setPropertyData("dataSource " + jndiName);
            publisher.setDescription("Used in Junit Test, Remove this one");
            publisherProxySession.addPublisher(internalAdmin, "TESTEXTOCSP", publisher);
            ret = true;
        } catch (PublisherExistsException pee) {
        	log.error(pee);
        }        
        assertTrue("Creating External OCSP Publisher failed", ret);
        int id = publisherProxySession.getPublisherId("TESTEXTOCSP");
        publisherProxySession.testConnection(id);
        
        Certificate cert = CertTools.getCertfromByteArray(testcert);
        ArrayList<Integer> publishers = new ArrayList<Integer>();
        publishers.add(Integer.valueOf(publisherProxySession.getPublisherId("TESTEXTOCSP")));

        ret = publisherSession.storeCertificate(admin, publishers, cert, "test05", "foo123", null, null, SecConst.CERT_ACTIVE, SecConst.CERTTYPE_ENDENTITY, -1, RevokedCertInfo.NOT_REVOKED, "foo", SecConst.CERTPROFILE_FIXED_ENDUSER, new Date().getTime(), null);
        assertTrue("Error storing certificate to external ocsp publisher", ret);

        publisherProxySession.revokeCertificate(internalAdmin, publishers, cert, "test05", null, null, SecConst.CERTTYPE_ENDENTITY, RevokedCertInfo.REVOCATION_REASON_CACOMPROMISE, new Date().getTime(), "foo", SecConst.CERTPROFILE_FIXED_ENDUSER, new Date().getTime());
	    log.trace("<test14ExternalOCSPPublisherCustom()");
    }
    
    @Test
    public void test15ExternalOCSPPublisher() throws Exception {
	    log.trace(">test15ExternalOCSPPublisher()");
        boolean ret = false;

        ret = false;
		try {
			ValidationAuthorityPublisher publisher = new ValidationAuthorityPublisher();
		    // We use the default EjbcaDS datasource here, because it probably exists during our junit test run
			final String jndiPrefix = configurationSession.getProperty(InternalConfiguration.CONFIG_DATASOURCENAMEPREFIX);
			final String jndiName = jndiPrefix + configurationSession.getProperty(DatabaseConfiguration.CONFIG_DATASOURCENAME);
            log.debug("jndiPrefix=" + jndiPrefix + " jndiName=" + jndiName);
            publisher.setDataSource(jndiName);
            publisher.setDescription("Used in Junit Test, Remove this one");
            publisherProxySession.addPublisher(internalAdmin, "TESTEXTOCSP2", publisher);
            ret = true;
        } catch (PublisherExistsException pee) {
        	log.error(pee);
        }        
        assertTrue("Creating External OCSP Publisher failed", ret);
        int id = publisherProxySession.getPublisherId("TESTEXTOCSP2");
        publisherProxySession.testConnection(id);
        
        Certificate cert = CertTools.getCertfromByteArray(testcert);
        ArrayList<Integer> publishers = new ArrayList<Integer>();
        publishers.add(Integer.valueOf(publisherProxySession.getPublisherId("TESTEXTOCSP2")));
        
        long date = new Date().getTime();
        ret = publisherSession.storeCertificate(admin, publishers, cert, "test05", "foo123", null, null, SecConst.CERT_ACTIVE, SecConst.CERTTYPE_ENDENTITY, -1, RevokedCertInfo.NOT_REVOKED, "foo", SecConst.CERTPROFILE_FIXED_ENDUSER, date, null);
        assertTrue("Error storing certificate to external ocsp publisher", ret);

        CertificateInfo info = certificateStoreSession.getCertificateInfo(CertTools.getFingerprintAsString(cert));
        assertEquals(SecConst.CERTPROFILE_FIXED_ENDUSER, info.getCertificateProfileId());
        assertEquals("foo", info.getTag());
        assertEquals(date, info.getUpdateTime().getTime());

        date = date + 12345;
        publisherProxySession.revokeCertificate(internalAdmin, publishers, cert, "test05", null, null, SecConst.CERTTYPE_ENDENTITY, RevokedCertInfo.REVOCATION_REASON_CACOMPROMISE, new Date().getTime(), "foobar", 12345, date);

        info = certificateStoreSession.getCertificateInfo(CertTools.getFingerprintAsString(cert));
        assertEquals(12345, info.getCertificateProfileId());
        assertEquals("foobar", info.getTag());
        assertEquals(date, info.getUpdateTime().getTime());

        String issuerDn = CertTools.getIssuerDN(CertTools.getCRLfromByteArray(testcrl));
        // Test storing and updating CRLs as well
        publisherSession.storeCRL(admin, publishers, testcrl, "test05", 1, issuerDn);
        publisherSession.storeCRL(admin, publishers, testcrl, "test05", 1, issuerDn);
        
        log.trace("<test15ExternalOCSPPublisher()");
    }

    /**
     * removes all publishers
     *
     * @throws Exception error
     */
    @Test
    public void test99removePublishers() throws Exception {
        log.trace(">test99removePublishers()");
        boolean ret = true;
        try {
        	publisherProxySession.removePublisher(internalAdmin, "TESTLDAP");            
        } catch (Exception pee) {ret = false;}
        try {
        	publisherProxySession.removePublisher(internalAdmin, "TESTAD");
        } catch (Exception pee) {ret = false;}
        try {
        	publisherProxySession.removePublisher(internalAdmin, "TESTNEWDUMMYCUSTOM");
        } catch (Exception pee) {ret = false;}
        try {
        	publisherProxySession.removePublisher(internalAdmin, "TESTCLONEDUMMYCUSTOM");
        } catch (Exception pee) {ret = false;}
        try {
        	publisherProxySession.removePublisher(internalAdmin, "TESTEXTOCSP");            
        } catch (Exception pee) {ret = false;}
        try {
        	publisherProxySession.removePublisher(internalAdmin, "TESTEXTOCSP2");            
        } catch (Exception pee) {ret = false;}
        assertTrue("Removing Publisher failed", ret);
        
        log.trace("<test99removePublishers()");
    }

} // TestPublisher
