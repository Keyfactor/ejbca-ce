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

package se.anatom.ejbca.hardtoken;

import java.util.Arrays;
import javax.naming.Context;
import javax.naming.NamingException;

import junit.framework.TestCase;
import org.apache.log4j.Logger;
import se.anatom.ejbca.hardtoken.hardtokenprofiles.EnhancedEIDProfile;
import se.anatom.ejbca.hardtoken.hardtokenprofiles.HardTokenProfile;
import se.anatom.ejbca.hardtoken.hardtokenprofiles.SwedishEIDProfile;
import se.anatom.ejbca.log.Admin;
import se.anatom.ejbca.util.CertTools;

/**
 * Tests the hard token profile entity bean.
 *
 * @version $Id: TestHardTokenProfile.java,v 1.1 2004-06-10 16:17:44 sbailliez Exp $
 */
public class TestHardTokenProfile extends TestCase {
    private static Logger log = Logger.getLogger(TestHardTokenProfile.class);
    private IHardTokenSessionRemote cacheAdmin;

    private static int SVGFILESIZE = 512 * 1024; // 1/2 Mega char


    private static IHardTokenSessionHome cacheHome;

    private static final Admin admin = new Admin(Admin.TYPE_INTERNALUSER);

    /**
     * Creates a new TestHardTokenProfile object.
     *
     * @param name name
     */
    public TestHardTokenProfile(String name) {
        super(name);
    }

    protected void setUp() throws Exception {

        log.debug(">setUp()");
        CertTools.installBCProvider();

        if (cacheAdmin == null) {
            if (cacheHome == null) {
                Context jndiContext = getInitialContext();
                Object obj1 = jndiContext.lookup("HardTokenSession");
                cacheHome = (IHardTokenSessionHome) javax.rmi.PortableRemoteObject.narrow(obj1, IHardTokenSessionHome.class);

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
     * adds a profile to the database
     *
     * @throws Exception error
     */
    public void test01AddHardTokenProfile() throws Exception {
        log.debug(">test01AddHardTokenProfile()");
        boolean ret = false;
        try {
            SwedishEIDProfile profile = new SwedishEIDProfile();
            EnhancedEIDProfile profile2 = new EnhancedEIDProfile();


            String svgdata = createSVGData();
            profile.setPINEnvelopeData(svgdata);
            profile2.setIsKeyRecoverable(EnhancedEIDProfile.CERTUSAGE_ENC, true);


            cacheAdmin.addHardTokenProfile(admin, "SWETEST", profile);
            cacheAdmin.addHardTokenProfile(admin, "ENHTEST", profile2);

            SwedishEIDProfile profile3 = (SwedishEIDProfile) cacheAdmin.getHardTokenProfile(admin, "SWETEST");
            EnhancedEIDProfile profile4 = (EnhancedEIDProfile) cacheAdmin.getHardTokenProfile(admin, "ENHTEST");

            String svgdata2 = profile3.getPINEnvelopeData();

            assertTrue("Saving SVG Data failed", svgdata.equals(svgdata2));
            assertTrue("Saving Hard Token Profile failed", profile4.getIsKeyRecoverable(EnhancedEIDProfile.CERTUSAGE_ENC));

            ret = true;
        } catch (HardTokenProfileExistsException pee) {
        }

        assertTrue("Creating Hard Token Profile failed", ret);
        log.debug("<test01AddHardTokenProfile()");
    }

    /**
     * renames profile
     *
     * @throws Exception error
     */
    public void test02RenameHardTokenProfile() throws Exception {
        log.debug(">test02RenameHardTokenProfile()");

        boolean ret = false;
        try {
            cacheAdmin.renameHardTokenProfile(admin, "SWETEST", "SWETEST2");
            ret = true;
        } catch (HardTokenProfileExistsException pee) {
        }
        assertTrue("Renaming Hard Token Profile failed", ret);

        log.debug("<test02RenameHardTokenProfile()");
    }

    /**
     * clones profile
     *
     * @throws Exception error
     */
    public void test03CloneHardTokenProfile() throws Exception {
        log.debug(">test03CloneHardTokenProfile()");

        boolean ret = false;
        try {
            cacheAdmin.cloneHardTokenProfile(admin, "SWETEST2", "SWETEST");
            ret = true;
        } catch (HardTokenProfileExistsException pee) {
        }
        assertTrue("Cloning Hard Token Profile failed", ret);

        log.debug("<test03CloneHardTokenProfile()");
    }


    /**
     * edits profile
     *
     * @throws Exception error
     */
    public void test04EditHardTokenProfile() throws Exception {
        log.debug(">test04EditHardTokenProfile()");

        boolean ret = false;

        HardTokenProfile profile = cacheAdmin.getHardTokenProfile(admin, "ENHTEST");


        profile.setHardTokenSNPrefix("11111");

        cacheAdmin.changeHardTokenProfile(admin, "ENHTEST", profile);
        ret = true;

        assertTrue("Editing HardTokenProfile failed", ret);


        log.debug("<test04EditHardTokenProfile()");
    }


    /**
     * removes all profiles
     *
     * @throws Exception error
     */
    public void test05removeHardTokenProfiles() throws Exception {
        log.debug(">test05removeHardTokenProfiles()");
        boolean ret = false;
        try {
            // Remove all except ENHTEST
            cacheAdmin.removeHardTokenProfile(admin, "SWETEST");
            cacheAdmin.removeHardTokenProfile(admin, "SWETEST2");
            cacheAdmin.removeHardTokenProfile(admin, "ENHTEST");
            ret = true;
        } catch (Exception pee) {
        }
        assertTrue("Removing Hard Token Profile failed", ret);

        log.debug("<test05removeHardTokenProfiles()");
    }

    private String createSVGData() {
        char[] chararray = new char[SVGFILESIZE];
        Arrays.fill(chararray, 'a');

        return new String(chararray);
    }


}
