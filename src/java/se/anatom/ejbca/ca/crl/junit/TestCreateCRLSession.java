package se.anatom.ejbca.ca.crl.junit;

import java.util.Random;
import java.util.*;
import java.lang.Integer;
import java.io.*;
import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.KeyPairGenerator;
import java.security.cert.*;
import java.security.interfaces.*;
import java.security.Provider;
import java.security.Security;

import javax.naming.InitialContext;
import javax.naming.Context;
import javax.naming.NamingException;
import java.rmi.RemoteException;
import javax.ejb.DuplicateKeyException;

import se.anatom.ejbca.ca.sign.*;
import se.anatom.ejbca.ca.crl.*;
import se.anatom.ejbca.ca.store.*;
import se.anatom.ejbca.util.*;
import se.anatom.ejbca.*;
import se.anatom.ejbca.SecConst;

import org.apache.log4j.*;
import junit.framework.*;


/** Tests CRL session (agentrunner and certificatesession).
 *
 * @version $Id: TestCreateCRLSession.java,v 1.4 2002-05-23 14:28:27 anatom Exp $
 */
public class TestCreateCRLSession extends TestCase {

    static Category cat = Category.getInstance( TestCreateCRLSession.class.getName() );
    private static Context ctx;
    private static IJobRunnerSessionHome  home;
    private static IJobRunnerSessionRemote remote;
    private static ICertificateStoreSessionHome storehome;
    private static ICertificateStoreSessionRemote storeremote;

    public TestCreateCRLSession(String name) {
        super(name);
    }
    protected void setUp() throws Exception {
        cat.debug(">setUp()");
        ctx = getInitialContext();
        Object obj = ctx.lookup("CreateCRLSession");
        home = (IJobRunnerSessionHome) javax.rmi.PortableRemoteObject.narrow(obj, IJobRunnerSessionHome.class);
        remote = home.create();
        Object obj1 = ctx.lookup("CertificateStoreSession");
        storehome = (ICertificateStoreSessionHome) javax.rmi.PortableRemoteObject.narrow(obj1, ICertificateStoreSessionHome.class);
        storeremote = storehome.create();
        cat.debug("<setUp()");
    }
    protected void tearDown() throws Exception {
    }
    private Context getInitialContext() throws NamingException {
        cat.debug(">getInitialContext");
        Context ctx = new javax.naming.InitialContext();
        cat.debug("<getInitialContext");
        return ctx;
    }

    public void test01CreateNewCRL() throws Exception {
        cat.debug(">test01CreateNewCRL()");
        remote.run();
        cat.debug("<test01CreateNewCRL()");
    }
    public void test02LastCRL() throws Exception {
        cat.debug(">test02LastCRL()");
        // Get number of last CRL
        int number = storeremote.getLastCRLNumber();
        cat.debug("Last CRLNumber = "+number);
        byte[] crl = storeremote.getLastCRL();
        assertNotNull("Could not get CRL", crl);
        X509CRL x509crl = CertTools.getCRLfromByteArray(crl);
        //FileOutputStream fos = new FileOutputStream("testcrl.der");
        //fos.write(crl);
        //fos.close();
        cat.debug("<test02LastCRL()");
    }
    public void test03CheckNumberofRevokedCerts() throws Exception {
        cat.debug(">test03CheckNumberofRevokedCerts()");
        // Get number of last CRL
        Collection revfp = storeremote.listRevokedCertificates();
        cat.debug("Number of revoked certificates="+revfp.size());
        byte[] crl = storeremote.getLastCRL();
        assertNotNull("Could not get CRL", crl);
        X509CRL x509crl = CertTools.getCRLfromByteArray(crl);
        Set revset = x509crl.getRevokedCertificates();
        int revsize = 0;
        if (revset != null)
            revsize = revset.size();
            assertEquals(revfp.size(), revsize);
        cat.debug("<test03CheckNumberofRevokedCerts()");
    }

}
