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

package se.anatom.ejbca.ca.caadmin;

import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Collection;
import javax.naming.Context;
import javax.naming.NamingException;

import junit.framework.TestCase;
import org.apache.log4j.Logger;
import se.anatom.ejbca.SecConst;
import se.anatom.ejbca.authorization.IAuthorizationSessionHome;
import se.anatom.ejbca.authorization.IAuthorizationSessionRemote;
import se.anatom.ejbca.ca.caadmin.extendedcaservices.ExtendedCAServiceInfo;
import se.anatom.ejbca.ca.caadmin.extendedcaservices.OCSPCAServiceInfo;
import se.anatom.ejbca.ca.exception.CAExistsException;
import se.anatom.ejbca.log.Admin;

/**
 * Tests the ca data entity bean.
 *
 * @version $Id: TestCAs.java,v 1.1 2004-06-10 16:17:43 sbailliez Exp $
 */
public class TestCAs extends TestCase {
    private static Logger log = Logger.getLogger(TestCAs.class);

    private ICAAdminSessionRemote cacheAdmin;


    private static ICAAdminSessionHome cacheHome;

    private static final Admin admin = new Admin(Admin.TYPE_INTERNALUSER);

    /**
     * Creates a new TestCAs object.
     *
     * @param name name
     */
    public TestCAs(String name) {
        super(name);
    }

    protected void setUp() throws Exception {

        log.debug(">setUp()");

        if (cacheAdmin == null) {
            if (cacheHome == null) {
                Context jndiContext = getInitialContext();
                Object obj1 = jndiContext.lookup("CAAdminSession");
                cacheHome = (ICAAdminSessionHome) javax.rmi.PortableRemoteObject.narrow(obj1, ICAAdminSessionHome.class);
            }

            cacheAdmin = cacheHome.create();
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
     * adds a CA to the database.
     *
     * It also checks that the CA is stored correctly.
     *
     * @throws Exception error
     */
    public void test01AddCA() throws Exception {
        log.debug(">test01AddCA()");
        boolean ret = false;
        try {

            Context context = getInitialContext();
            IAuthorizationSessionHome authorizationsessionhome = (IAuthorizationSessionHome) javax.rmi.PortableRemoteObject.narrow(context.lookup("AuthorizationSession"), IAuthorizationSessionHome.class);
            IAuthorizationSessionRemote authorizationsession = authorizationsessionhome.create();
            authorizationsession.initialize(admin, "CN=TEST".hashCode());

            SoftCATokenInfo catokeninfo = new SoftCATokenInfo();
            catokeninfo.setKeySize(2048);
            catokeninfo.setAlgorithm(SoftCATokenInfo.KEYALGORITHM_RSA);
            catokeninfo.setSignatureAlgorithm(CATokenInfo.SIGALG_SHA_WITH_RSA);
            // Create and active OSCP CA Service.
            ArrayList extendedcaservices = new ArrayList();
            extendedcaservices.add(new OCSPCAServiceInfo(ExtendedCAServiceInfo.STATUS_ACTIVE,
                    "CN=OCSPSignerCertificate, " + "CN=TEST",
                    "",
                    2048,
                    OCSPCAServiceInfo.KEYALGORITHM_RSA));


            X509CAInfo cainfo = new X509CAInfo("CN=TEST",
                    "TEST", SecConst.CA_ACTIVE,
                    "", SecConst.CERTPROFILE_FIXED_ROOTCA,
                    1,
                    null, // Expiretime
                    CAInfo.CATYPE_X509,
                    CAInfo.SELFSIGNED,
                    (Collection) null,
                    catokeninfo,
                    "Initial CA",
                    -1, null,
                    null, // PolicyId
                    24, // CRLPeriod
                    (Collection) new ArrayList(),
                    true, // Authority Key Identifier
                    false, // Authority Key Identifier Critical
                    true, // CRL Number
                    false, // CRL Number Critical
                    true, // Finish User
                    extendedcaservices);


            cacheAdmin.createCA(admin, cainfo);


            CAInfo info = cacheAdmin.getCAInfo(admin, "TEST");

            X509Certificate cert = (X509Certificate) info.getCertificateChain().iterator().next();
            assertTrue("Error in created ca certificate", cert.getSubjectDN().toString().equals("CN=TEST"));
            assertTrue("Creating CA failed", info.getSubjectDN().equals("CN=TEST"));

            ret = true;
        } catch (CAExistsException pee) {
        }

        assertTrue("Creating CA failed", ret);
        log.debug("<test01AddCA()");
    }

    /**
     * renames CA in database.
     *
     * @throws Exception error
     */
    public void test02RenameCA() throws Exception {
        log.debug(">test02RenameCA()");

        boolean ret = false;
        try {
            cacheAdmin.renameCA(admin, "TEST", "TEST2");
            cacheAdmin.renameCA(admin, "TEST2", "TEST");
            ret = true;
        } catch (CAExistsException cee) {
        }
        assertTrue("Renaming CA failed", ret);

        log.debug("<test02RenameCA()");
    }


    /**
     * edits ca and checks that it's stored correctly.
     *
     * @throws Exception error
     */
    public void test03EditCA() throws Exception {
        log.debug(">test03EditCA()");

        boolean ret = false;

        X509CAInfo info = (X509CAInfo) cacheAdmin.getCAInfo(admin, "TEST");

        info.setCRLPeriod(33);

        cacheAdmin.editCA(admin, info);

        X509CAInfo info2 = (X509CAInfo) cacheAdmin.getCAInfo(admin, "TEST");
        assertTrue("Editing CA failed", info2.getCRLPeriod() == 33);

        log.debug("<test03EditCA()");
    }


}
