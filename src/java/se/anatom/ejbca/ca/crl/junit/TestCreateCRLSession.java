package se.anatom.ejbca.ca.crl.junit;

import java.security.cert.X509CRL;
import java.util.*;

import javax.naming.Context;
import javax.naming.NamingException;

import se.anatom.ejbca.ca.store.*;
import se.anatom.ejbca.util.*;
import se.anatom.ejbca.*;
import se.anatom.ejbca.log.Admin;

import org.apache.log4j.Logger;
import junit.framework.*;


/** Tests CRL session (agentrunner and certificatesession).
 *
 * @version $Id: TestCreateCRLSession.java,v 1.8 2003-02-12 11:23:15 scop Exp $
 */
public class TestCreateCRLSession extends TestCase {

    private static Logger log = Logger.getLogger(TestCreateCRLSession.class);
    private static Context ctx;
    private static IJobRunnerSessionHome  home;
    private static IJobRunnerSessionRemote remote;
    private static ICertificateStoreSessionHome storehome;
    private static ICertificateStoreSessionRemote storeremote;

    public TestCreateCRLSession(String name) {
        super(name);
    }
    protected void setUp() throws Exception {
        log.debug(">setUp()");
        ctx = getInitialContext();
        Object obj = ctx.lookup("CreateCRLSession");
        home = (IJobRunnerSessionHome) javax.rmi.PortableRemoteObject.narrow(obj, IJobRunnerSessionHome.class);
        remote = home.create();
        Object obj1 = ctx.lookup("CertificateStoreSession");
        storehome = (ICertificateStoreSessionHome) javax.rmi.PortableRemoteObject.narrow(obj1, ICertificateStoreSessionHome.class);
        storeremote = storehome.create();
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

    public void test01CreateNewCRL() throws Exception {
        log.debug(">test01CreateNewCRL()");
        remote.run(new Admin(Admin.TYPE_INTERNALUSER));
        log.debug("<test01CreateNewCRL()");
    }
    public void test02LastCRL() throws Exception {
        log.debug(">test02LastCRL()");
        // Get number of last CRL
        int number = storeremote.getLastCRLNumber(new Admin(Admin.TYPE_INTERNALUSER));
        log.debug("Last CRLNumber = "+number);
        byte[] crl = storeremote.getLastCRL(new Admin(Admin.TYPE_INTERNALUSER));
        assertNotNull("Could not get CRL", crl);
        X509CRL x509crl = CertTools.getCRLfromByteArray(crl);
        //FileOutputStream fos = new FileOutputStream("testcrl.der");
        //fos.write(crl);
        //fos.close();
        log.debug("<test02LastCRL()");
    }
    public void test03CheckNumberofRevokedCerts() throws Exception {
        log.debug(">test03CheckNumberofRevokedCerts()");
        // Get number of last CRL
        Collection revfp = storeremote.listRevokedCertificates(new Admin(Admin.TYPE_INTERNALUSER));
        log.debug("Number of revoked certificates="+revfp.size());
        byte[] crl = storeremote.getLastCRL(new Admin(Admin.TYPE_INTERNALUSER));
        assertNotNull("Could not get CRL", crl);
        X509CRL x509crl = CertTools.getCRLfromByteArray(crl);
        Set revset = x509crl.getRevokedCertificates();
        int revsize = 0;
        if (revset != null)
            revsize = revset.size();
            assertEquals(revfp.size(), revsize);
        log.debug("<test03CheckNumberofRevokedCerts()");
    }

}
