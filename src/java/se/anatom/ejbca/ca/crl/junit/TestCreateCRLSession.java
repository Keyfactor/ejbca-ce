package se.anatom.ejbca.ca.crl.junit;

import java.security.cert.X509CRL;
import java.util.*;

import javax.naming.Context;
import javax.naming.NamingException;

import se.anatom.ejbca.ca.store.*;
import se.anatom.ejbca.util.*;
import se.anatom.ejbca.*;
import se.anatom.ejbca.log.Admin;
import se.anatom.ejbca.ca.caadmin.ICAAdminSessionHome;
import se.anatom.ejbca.ca.caadmin.ICAAdminSessionRemote;
import se.anatom.ejbca.ca.caadmin.CAInfo;

import org.apache.log4j.Logger;
import junit.framework.*;

/**
 * Tests CRL session (agentrunner and certificatesession).
 *
 * @version $Id: TestCreateCRLSession.java,v 1.12 2003-11-03 14:00:49 anatom Exp $
 */
public class TestCreateCRLSession extends TestCase {

    private static Logger log = Logger.getLogger(TestCreateCRLSession.class);
    private static Context ctx;
    private static IJobRunnerSessionHome  home;
    private static IJobRunnerSessionRemote remote;
    private static ICertificateStoreSessionHome storehome;
    private static ICertificateStoreSessionRemote storeremote;
    private static Admin admin;
    private static int caid;
    private static String cadn;

    /**
     * Creates a new TestCreateCRLSession object.
     *
     * @param name name
     */
    public TestCreateCRLSession(String name) {
        super(name);
    }

    protected void setUp() throws Exception {
        log.debug(">setUp()");
        ctx = getInitialContext();

        admin = new Admin(Admin.TYPE_INTERNALUSER);

        Object obj = ctx.lookup("CreateCRLSession");
        home = (IJobRunnerSessionHome) javax.rmi.PortableRemoteObject.narrow(obj, IJobRunnerSessionHome.class);
        remote = home.create();

        Object obj1 = ctx.lookup("CertificateStoreSession");
        storehome = (ICertificateStoreSessionHome) javax.rmi.PortableRemoteObject.narrow(obj1, ICertificateStoreSessionHome.class);
        storeremote = storehome.create();

        obj = ctx.lookup("CAAdminSession");
        ICAAdminSessionHome cahome = (ICAAdminSessionHome) javax.rmi.PortableRemoteObject.narrow(obj, ICAAdminSessionHome.class);
        ICAAdminSessionRemote casession = cahome.create();          
        Collection caids = casession.getAvailableCAs(admin);
        Iterator iter = caids.iterator();
        if (iter.hasNext()) {
            caid = ((Integer)iter.next()).intValue();
            CAInfo cainfo = casession.getCAInfo(admin, caid);
            cadn = cainfo.getSubjectDN();
        } else {
            assertTrue("No active CA! Must have at least one active CA to run tests!", false);
        }
        
        
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
     * creates new crl
     *
     * @throws Exception error
     */
    public void test01CreateNewCRL() throws Exception {
        log.debug(">test01CreateNewCRL()");
        remote.run(admin, cadn);
        log.debug("<test01CreateNewCRL()");
    }

    /**
     * gets last crl
     *
     * @throws Exception error
     */
    public void test02LastCRL() throws Exception {
        log.debug(">test02LastCRL()");

        // Get number of last CRL
        int number = storeremote.getLastCRLNumber(admin,cadn);
        log.debug("Last CRLNumber = "+number);
        byte[] crl = storeremote.getLastCRL(admin,cadn);
        assertNotNull("Could not get CRL", crl);

        X509CRL x509crl = CertTools.getCRLfromByteArray(crl);

        //FileOutputStream fos = new FileOutputStream("testcrl.der");
        //fos.write(crl);
        //fos.close();
        log.debug("<test02LastCRL()");
    }

    /**
     * check revoked certificates
     *
     * @throws Exception error
     */
    public void test03CheckNumberofRevokedCerts() throws Exception {
        log.debug(">test03CheckNumberofRevokedCerts()");

        // Get number of last CRL
        Collection revfp = storeremote.listRevokedCertificates(admin,cadn);
        log.debug("Number of revoked certificates="+revfp.size());
        byte[] crl = storeremote.getLastCRL(admin, cadn);
        assertNotNull("Could not get CRL", crl);

        X509CRL x509crl = CertTools.getCRLfromByteArray(crl);
        Set revset = x509crl.getRevokedCertificates();
        int revsize = 0;

        if (revset != null) {
            revsize = revset.size();
            assertEquals(revfp.size(), revsize);
        }  
        log.debug("<test03CheckNumberofRevokedCerts()");
      }
 
}
