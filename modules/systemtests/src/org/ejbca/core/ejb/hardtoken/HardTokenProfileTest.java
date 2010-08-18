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

package org.ejbca.core.ejb.hardtoken;

import java.util.Arrays;

import junit.framework.TestCase;

import org.apache.log4j.Logger;
import org.ejbca.core.model.hardtoken.HardTokenProfileExistsException;
import org.ejbca.core.model.hardtoken.profiles.EnhancedEIDProfile;
import org.ejbca.core.model.hardtoken.profiles.HardTokenProfile;
import org.ejbca.core.model.hardtoken.profiles.SwedishEIDProfile;
import org.ejbca.core.model.hardtoken.profiles.TurkishEIDProfile;
import org.ejbca.core.model.log.Admin;
import org.ejbca.util.CryptoProviderTools;
import org.ejbca.util.InterfaceCache;

/**
 * Tests the hard token profile entity bean.
 * 
 * @version $Id$
 */
public class HardTokenProfileTest extends TestCase {
    private static Logger log = Logger.getLogger(HardTokenProfileTest.class);

    private HardTokenSessionRemote hardTokenSession = InterfaceCache.getHardTokenSession();

    private static int SVGFILESIZE = 512 * 1024; // 1/2 Mega char

    private static final Admin admin = new Admin(Admin.TYPE_INTERNALUSER);

    public HardTokenProfileTest(String name) {
        super(name);
    }

    public void setUp() throws Exception {
        CryptoProviderTools.installBCProvider();
    }

    public void tearDown() throws Exception {
    }

    /**
     * adds a profile to the database
     * @throws HardTokenProfileExistsException 
     * 
     * @throws Exception
     *             error
     */
    public void test01AddHardTokenProfile() throws HardTokenProfileExistsException {

        SwedishEIDProfile profile = new SwedishEIDProfile();
        EnhancedEIDProfile profile2 = new EnhancedEIDProfile();
        TurkishEIDProfile turprofile = new TurkishEIDProfile();

        String svgdata = createSVGData();
        profile.setPINEnvelopeData(svgdata);
        profile2.setIsKeyRecoverable(EnhancedEIDProfile.CERTUSAGE_ENC, true);

        hardTokenSession.addHardTokenProfile(admin, "SWETEST", profile);
        hardTokenSession.addHardTokenProfile(admin, "ENHTEST", profile2);
        hardTokenSession.addHardTokenProfile(admin, "TURTEST", turprofile);

        SwedishEIDProfile profile3 = (SwedishEIDProfile) hardTokenSession.getHardTokenProfile(admin, "SWETEST");
        EnhancedEIDProfile profile4 = (EnhancedEIDProfile) hardTokenSession.getHardTokenProfile(admin, "ENHTEST");
        TurkishEIDProfile turprofile2 = (TurkishEIDProfile) hardTokenSession.getHardTokenProfile(admin, "TURTEST");

        String svgdata2 = profile3.getPINEnvelopeData();

        assertTrue("Saving SVG Data failed", svgdata.equals(svgdata2));
        assertTrue("Saving Hard Token Profile failed", profile4.getIsKeyRecoverable(EnhancedEIDProfile.CERTUSAGE_ENC));
        assertTrue("Saving Turkish Hard Token Profile failed", (turprofile2 != null));
    }

    /**
     * renames profile
     * 
     * @throws Exception
     *             error
     */
    public void test02RenameHardTokenProfile() throws Exception {
        log.trace(">test02RenameHardTokenProfile()");

        boolean ret = false;
        try {
            hardTokenSession.renameHardTokenProfile(admin, "SWETEST", "SWETEST2");
            ret = true;
        } catch (HardTokenProfileExistsException pee) {
            log.debug("", pee);
        }
        assertTrue("Renaming Hard Token Profile failed", ret);

        log.trace("<test02RenameHardTokenProfile()");
    }

    /**
     * clones profile
     * 
     * @throws Exception
     *             error
     */
    public void test03CloneHardTokenProfile() throws Exception {
        log.trace(">test03CloneHardTokenProfile()");

        boolean ret = false;
        try {
            hardTokenSession.cloneHardTokenProfile(admin, "SWETEST2", "SWETEST");
            ret = true;
        } catch (HardTokenProfileExistsException pee) {
            log.debug("", pee);
        }
        assertTrue("Cloning Hard Token Profile failed", ret);

        log.trace("<test03CloneHardTokenProfile()");
    }

    /**
     * edits profile
     * 
     * @throws Exception
     *             error
     */
    public void test04EditHardTokenProfile() throws Exception {
        log.trace(">test04EditHardTokenProfile()");
        boolean ret = false;
        HardTokenProfile profile = hardTokenSession.getHardTokenProfile(admin, "ENHTEST");
        profile.setHardTokenSNPrefix("11111");
        hardTokenSession.changeHardTokenProfile(admin, "ENHTEST", profile);
        ret = true;
        assertTrue("Editing HardTokenProfile failed", ret);
        log.trace("<test04EditHardTokenProfile()");
    }

    /**
     * removes all profiles
     * 
     * @throws Exception
     *             error
     */
    public void test05removeHardTokenProfiles() throws Exception {
        log.trace(">test05removeHardTokenProfiles()");
        boolean ret = false;
        try {
            // Remove all except ENHTEST
            hardTokenSession.removeHardTokenProfile(admin, "SWETEST");
            hardTokenSession.removeHardTokenProfile(admin, "SWETEST2");
            hardTokenSession.removeHardTokenProfile(admin, "ENHTEST");
            hardTokenSession.removeHardTokenProfile(admin, "TURTEST");
            ret = true;
        } catch (Exception pee) {
            log.debug("", pee);
        }
        assertTrue("Removing Hard Token Profile failed", ret);
        log.trace("<test05removeHardTokenProfiles()");
    }

    private String createSVGData() {
        char[] chararray = new char[SVGFILESIZE];
        Arrays.fill(chararray, 'a');

        return new String(chararray);
    }

}
