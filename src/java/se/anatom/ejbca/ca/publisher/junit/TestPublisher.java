package se.anatom.ejbca.ca.publisher.junit;

import java.security.cert.*;
import java.util.ArrayList;

import javax.naming.Context;
import javax.naming.NamingException;


import se.anatom.ejbca.SecConst;
import se.anatom.ejbca.ca.exception.PublisherExistsException;
import se.anatom.ejbca.ca.publisher.*;

import se.anatom.ejbca.util.*;
import se.anatom.ejbca.log.Admin;

import org.apache.log4j.Logger;
import junit.framework.*;


/**
 * Tests Publishers.
 *
 * @version $Id: TestPublisher.java,v 1.2 2004-03-14 13:49:48 herrvendil Exp $
 */
public class TestPublisher extends TestCase {

    static byte[] testcert = Base64.decode(
    ("MIICWzCCAcSgAwIBAgIIJND6Haa3NoAwDQYJKoZIhvcNAQEFBQAwLzEPMA0GA1UE"
    +"AxMGVGVzdENBMQ8wDQYDVQQKEwZBbmFUb20xCzAJBgNVBAYTAlNFMB4XDTAyMDEw"
    +"ODA5MTE1MloXDTA0MDEwODA5MjE1MlowLzEPMA0GA1UEAxMGMjUxMzQ3MQ8wDQYD"
    +"VQQKEwZBbmFUb20xCzAJBgNVBAYTAlNFMIGdMA0GCSqGSIb3DQEBAQUAA4GLADCB"
    +"hwKBgQCQ3UA+nIHECJ79S5VwI8WFLJbAByAnn1k/JEX2/a0nsc2/K3GYzHFItPjy"
    +"Bv5zUccPLbRmkdMlCD1rOcgcR9mmmjMQrbWbWp+iRg0WyCktWb/wUS8uNNuGQYQe"
    +"ACl11SAHFX+u9JUUfSppg7SpqFhSgMlvyU/FiGLVEHDchJEdGQIBEaOBgTB/MA8G"
    +"A1UdEwEB/wQFMAMBAQAwDwYDVR0PAQH/BAUDAwegADAdBgNVHQ4EFgQUyxKILxFM"
    +"MNujjNnbeFpnPgB76UYwHwYDVR0jBBgwFoAUy5k/bKQ6TtpTWhsPWFzafOFgLmsw"
    +"GwYDVR0RBBQwEoEQMjUxMzQ3QGFuYXRvbS5zZTANBgkqhkiG9w0BAQUFAAOBgQAS"
    +"5wSOJhoVJSaEGHMPw6t3e+CbnEL9Yh5GlgxVAJCmIqhoScTMiov3QpDRHOZlZ15c"
    +"UlqugRBtORuA9xnLkrdxYNCHmX6aJTfjdIW61+o/ovP0yz6ulBkqcKzopAZLirX+"
    +"XSWf2uI9miNtxYMVnbQ1KPdEAt7Za3OQR6zcS0lGKg==").getBytes());

    static byte[] testcacert = Base64.decode(
    ("MIICLDCCAZWgAwIBAgIISDzEq64yCAcwDQYJKoZIhvcNAQEFBQAwLzEPMA0GA1UE"
    +"AxMGVGVzdENBMQ8wDQYDVQQKEwZBbmFUb20xCzAJBgNVBAYTAlNFMB4XDTAxMTIw"
    +"NDA5MzI1N1oXDTAzMTIwNDA5NDI1N1owLzEPMA0GA1UEAxMGVGVzdENBMQ8wDQYD"
    +"VQQKEwZBbmFUb20xCzAJBgNVBAYTAlNFMIGdMA0GCSqGSIb3DQEBAQUAA4GLADCB"
    +"hwKBgQCnhOvkaj+9Qmt9ZseVn8Jhl6ewTrAOK3c9usxBhiGs+TalGjuAK37bbnbZ"
    +"rlzCZpEsjSZYgXS++3NttiDbPzATkV/c33uIzBHjyk8/paOmTrkIux8hbIYMce+/"
    +"WTYnAM3J41mSuDMy2yZxZ72Yntzqg4UUXiW+JQDkhGx8ZtcSSwIBEaNTMFEwDwYD"
    +"VR0TAQH/BAUwAwEB/zAdBgNVHQ4EFgQUy5k/bKQ6TtpTWhsPWFzafOFgLmswHwYD"
    +"VR0jBBgwFoAUy5k/bKQ6TtpTWhsPWFzafOFgLmswDQYJKoZIhvcNAQEFBQADgYEA"
    +"gHzQLoqLobU43lKvQCiZbYWEXHTf3AdzUd6aMOYOM80iKS9kgrMsnKjp61IFCZwr"
    +"OcY1lOkpjADUTSqfVJWuF1z5k9c1bXnh5zu48LA2r2dlbHqG8twMQ+tPh1MYa3lV"
    +"ugWhKqArGEawICRPUZJrLy/eDbCgVB4QT3rC7rOJOH0=").getBytes());

    static byte[] testcrl = Base64.decode(
    ("MIIDEzCCAnwCAQEwDQYJKoZIhvcNAQEFBQAwLzEPMA0GA1UEAxMGVGVzdENBMQ8w"
    +"DQYDVQQKEwZBbmFUb20xCzAJBgNVBAYTAlNFFw0wMjAxMDMxMjExMTFaFw0wMjAx"
    +"MDIxMjExMTFaMIIB5jAZAggfi2rKt4IrZhcNMDIwMTAzMTIxMDUxWjAZAghAxdYk"
    +"7mJxkxcNMDIwMTAzMTIxMDUxWjAZAgg+lCCL+jumXxcNMDIwMTAzMTIxMDUyWjAZ"
    +"Agh4AAPpzSk/+hcNMDIwMTAzMTIxMDUyWjAZAghkhx9SFvxAgxcNMDIwMTAzMTIx"
    +"MDUyWjAZAggj4g5SUqaGvBcNMDIwMTAzMTIxMDUyWjAZAghT+nqB0c6vghcNMDIw"
    +"MTAzMTE1MzMzWjAZAghsBWMAA55+7BcNMDIwMTAzMTE1MzMzWjAZAgg8h0t6rKQY"
    +"ZhcNMDIwMTAzMTE1MzMzWjAZAgh7KFsd40ICwhcNMDIwMTAzMTE1MzM0WjAZAggA"
    +"kFlDNU8ubxcNMDIwMTAzMTE1MzM0WjAZAghyQfo1XNl0EBcNMDIwMTAzMTE1MzM0"
    +"WjAZAggC5Pz7wI/29hcNMDIwMTAyMTY1NDMzWjAZAggEWvzRRpFGoRcNMDIwMTAy"
    +"MTY1NDMzWjAZAggC7Q2W0iXswRcNMDIwMTAyMTY1NDMzWjAZAghrfwG3t6vCiBcN"
    +"MDIwMTAyMTY1NDMzWjAZAgg5C+4zxDGEjhcNMDIwMTAyMTY1NDMzWjAZAggX/olM"
    +"45KxnxcNMDIwMTAyMTY1NDMzWqAvMC0wHwYDVR0jBBgwFoAUy5k/bKQ6TtpTWhsP"
    +"WFzafOFgLmswCgYDVR0UBAMCAQQwDQYJKoZIhvcNAQEFBQADgYEAPvYDZofCOopw"
    +"OCKVGaK1aPpHkJmu5Xi1XtRGO9DhmnSZ28hrNu1A5R8OQI43Z7xFx8YK3S56GRuY"
    +"0EGU/RgM3AWhyTAps66tdyipRavKmH6MMrN4ypW/qbhsd4o8JE9pxxn9zsQaNxYZ"
    +"SNbXM2/YxkdoRSjkrbb9DUdCmCR/kEA=").getBytes());

    private static Logger log = Logger.getLogger(TestPublisher.class);
    private static Context ctx;
    private static IPublisherSessionRemote pub;

	private static final String CertificateData = null;
	private static final Admin admin = new Admin(Admin.TYPE_INTERNALUSER);

    /**
     * Creates a new TestPublisher object.
     *
     * @param name name
     */
    public TestPublisher(String name) {
        super(name);
    }

    protected void setUp() throws Exception {
        log.debug(">setUp()");
        ctx = getInitialContext();

        Object obj = ctx.lookup("PublisherSession");
        IPublisherSessionHome home = (IPublisherSessionHome) javax.rmi.PortableRemoteObject.narrow(obj,
                IPublisherSessionHome.class);
        pub = home.create();
        
        CertTools.installBCProvider();
        
        log.debug("<setUp()");        
        
    }

    protected void tearDown() throws Exception {
    }

    private Context getInitialContext() throws NamingException {
        log.debug(">getInitialContext");       
        Context ctx = new javax.naming.InitialContext();
        log.debug("<getInitialContext");

        return ctx;
    }

    /**
     * adds ldap publisher
     *
     * @throws Exception error
     */
    public void test01AddLDAPPublisher() throws Exception {
        log.debug(">test01AddLDAPPublisher()");
        boolean ret = false;
        try{
          LdapPublisher publisher = new LdapPublisher();
          publisher.setHostname("localhost");
          publisher.setDescription("Used in Junit Test, Remove this one");
          pub.addPublisher(admin,"TESTLDAP", publisher);
          ret = true;
        }catch(PublisherExistsException pee){}
                 
        assertTrue("Creating LDAP Publisher failed", ret); 
        log.debug("<test01AddLDAPPublisher()");
    }

    /**
     * adds ad publisher
     *
     * @throws Exception error
     */
    public void test02AddADPublisher() throws Exception {
        log.debug(">test02AddADPublisher() ");
        boolean ret = false;
        try{
          ActiveDirectoryPublisher publisher = new ActiveDirectoryPublisher();
          publisher.setHostname("localhost");
          publisher.setDescription("Used in Junit Test, Remove this one");
          pub.addPublisher(admin,"TESTAD", publisher);
          ret = true;
        }catch(PublisherExistsException pee){}
                 
        assertTrue("Creating AD Publisher failed", ret);         
        log.debug("<test02AddADPublisher() ");
    }

    /**
     * adds custom publisher
     *
     * @throws Exception error
     */
    public void test03AddCustomPublisher() throws Exception {
        log.debug(">test03AddCustomPublisher()");
        boolean ret = false;
        try{            
          CustomPublisherContainer publisher = new CustomPublisherContainer();
          publisher.setClassPath("se.anatom.ejbca.ca.publisher.DummyCustomPublisher");
          publisher.setDescription("Used in Junit Test, Remove this one");
          pub.addPublisher(admin,"TESTDUMMYCUSTOM", publisher);
          ret = true;
        }catch(PublisherExistsException pee){}
                 
        assertTrue("Creating Custom Publisher failed", ret);
        
        log.debug("<test03AddCustomPublisher()");
    }

    /**
     * renames publisher
     *
     * @throws Exception error
     */
    public void test04RenamePublisher() throws Exception {
        log.debug(">test04RenamePublisher()");

        boolean ret = false;
        try{                      
          pub.renamePublisher(admin, "TESTDUMMYCUSTOM", "TESTNEWDUMMYCUSTOM");          
          ret = true;
        }catch(PublisherExistsException pee){}                 
        assertTrue("Renaming Custom Publisher failed", ret);
        
        
        log.debug("<test04RenamePublisher()");
    }

    /**
     * clones publisher
     *
     * @throws Exception error
     */
    public void test05ClonePublisher() throws Exception {
        log.debug(">test05ClonePublisher()");

        boolean ret = false;
        try{                      
          pub.clonePublisher(admin, "TESTNEWDUMMYCUSTOM", "TESTCLONEDUMMYCUSTOM");          
          ret = true;
        }catch(PublisherExistsException pee){}                 
        assertTrue("Cloning Custom Publisher failed", ret);        
        
        log.debug("<test05ClonePublisher()");
    }
    
    
    
    /**
     * edits publisher
     *
     * @throws Exception error
     */	
    public void test06EditPublisher() throws Exception {
    	log.debug(">test06EditPublisher()");

        boolean ret = false;
        
        BasePublisher publisher = pub.getPublisher(admin, "TESTCLONEDUMMYCUSTOM");
        publisher.setDescription(publisher.getDescription().toUpperCase());
        pub.changePublisher(admin, "TESTCLONEDUMMYCUSTOM", publisher);                    
        ret = true;
                         
        assertTrue("Editing Custom Publisher failed", ret);        

    	
    	
    	log.debug("<test06EditPublisher()");
    }
    
    /**
     * stores a cert to the dummy publisher
     *
     * @throws Exception error
     */
    public void test07StoreCertToDummy() throws Exception {
       log.debug(">test07StoreCertToDummy()");    	
       X509Certificate cert = CertTools.getCertfromByteArray(testcert);
       ArrayList publishers = new ArrayList();
       publishers.add(new Integer(pub.getPublisherId(admin, "TESTNEWDUMMYCUSTOM")));
    	 
       boolean ret = pub.storeCertificate(new Admin(Admin.TYPE_INTERNALUSER), publishers, cert, "test05", null, se.anatom.ejbca.ca.store.CertificateData.CERT_ACTIVE, SecConst.CERTTYPE_ENDENTITY);
       assertTrue("Storing certificate to dummy publisher failed", ret); 
       log.debug("<test07StoreCertToDummyr()");
    }
    
    /**
     * stores a cert to the dummy publisher
     *
     * @throws Exception error
     */
    public void test08storeCRLToDummy() throws Exception {
    	log.debug(">test08storeCRLToDummy()");    	    	    	
    	 
    	ArrayList publishers = new ArrayList();
    	publishers.add(new Integer(pub.getPublisherId(admin, "TESTNEWDUMMYCUSTOM")));
    	boolean ret = pub.storeCRL(admin, publishers, testcrl, null, 1); 
    	assertTrue("Storing CRL to dummy publisher failed", ret);
    	
    	log.debug("<test08storeCRLToDummy()");
    }
    
    

    /**
     * removes all publishers
     *
     * @throws Exception error
     */
    public void test09removePublishers() throws Exception {
        log.debug(">test09removePublishers()");        
        boolean ret = false;
        try{
          pub.removePublisher(admin,"TESTLDAP");
          pub.removePublisher(admin,"TESTAD");
          pub.removePublisher(admin,"TESTNEWDUMMYCUSTOM");
          pub.removePublisher(admin,"TESTCLONEDUMMYCUSTOM");
          ret = true;
        }catch(Exception pee){}                 
        assertTrue("Removing Publisher failed", ret);
        
        log.debug("<test09removePublishers()");
    }
}
