/*************************************************************************
 *                                                                       *
 *  EJBCA Community: The OpenSource Certificate Authority                *
 *                                                                       *
 *  This software is free software; you can redistribute it and/or       *
 *  modify it under the terms of the GNU Lesser General Public           *
 *  License as published by the Free Software Foundation; either         *
 *  version 2.1 of the License, or any later version.                    *
 *                                                                       *
 *  See terms of license at gnu.org.                                     *
 *                                                                       *
 *************************************************************************/

package org.ejbca.ui.cli.ca;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertTrue;

import java.io.File;
import java.util.Collection;

import org.cesecore.CaTestUtils;
import org.cesecore.authentication.tokens.AuthenticationToken;
import org.cesecore.authentication.tokens.UsernamePrincipal;
import org.cesecore.certificates.ca.CA;
import org.cesecore.certificates.ca.CaSessionRemote;
import org.cesecore.keys.token.CryptoTokenTestUtils;
import org.cesecore.mock.authentication.tokens.TestAlwaysAllowLocalAuthenticationToken;
import org.cesecore.util.CryptoProviderTools;
import org.cesecore.util.EjbRemoteHelper;
import org.ejbca.core.ejb.ra.raadmin.EndEntityProfileSessionRemote;
import org.ejbca.core.model.SecConst;
import org.ejbca.core.model.ra.raadmin.EndEntityProfile;
import org.junit.After;
import org.junit.Before;
import org.junit.Test;

/**
 * System test class for CaImportProfilesCommand
 * 
 * @version $Id$
 */
public class CaExportImportProfilesCommandTest {

    private static final String CA_DN = "CN=CLI TEST CA 4712, O=PrimeKey,C=SE";
    private static final String tempDirectory = System.getProperty("java.io.tmpdir");
    private static final String PROFILES_DIR = tempDirectory + "/clitest_4712"; 
    private static final String[] CAEXPORTPROFILES_ARGS = { PROFILES_DIR };
    private static final String[] CAIMPORTPROFILES_ARGS = { PROFILES_DIR };

    private CaExportProfilesCommand caExportProfilesCommand;
    private CaImportProfilesCommand caImportProfilesCommand;
    
    private AuthenticationToken admin = new TestAlwaysAllowLocalAuthenticationToken(new UsernamePrincipal("CaExportImportProfilesCommandTest"));

    private CaSessionRemote caSession = EjbRemoteHelper.INSTANCE.getRemoteSession(CaSessionRemote.class);
    private EndEntityProfileSessionRemote eeProfileSession = EjbRemoteHelper.INSTANCE.getRemoteSession(EndEntityProfileSessionRemote.class);

    @Before
    public void setUp() throws Exception {
        CryptoProviderTools.installBCProvider();
        caExportProfilesCommand = new CaExportProfilesCommand();
        caImportProfilesCommand = new CaImportProfilesCommand();
        
        File f = new File(PROFILES_DIR);
        if (f.exists()) {
            f.delete();
        }
        // Create temp directory
        f.mkdir();        
    }

    @After
    public void tearDown() throws Exception {
        File f = new File(PROFILES_DIR);
        f.deleteOnExit();
    }

    /**
     * Test trivial happy path for execute, i.e, create an ordinary CA.
     * 
     * @throws Exception on serious error
     */
    @Test
    public void testExportImportProfiles() throws Exception {        

        final String profilename = "4712EEPROFILE";
        int caid = 0;
        int cryptoTokenId = 0;
        try {
            // Create a CA that we can delete later
            CA ca = CaTestUtils.createTestX509CAOptionalGenKeys(CA_DN, "foo".toCharArray(), false, false);
            cryptoTokenId = ca.getCAToken().getCryptoTokenId();
            caid = ca.getCAId();
            caSession.addCA(admin, ca);

            // Create an End entity profile to export and import
            EndEntityProfile profile = new EndEntityProfile();
            profile.setValue(EndEntityProfile.AVAILCAS, 0, Integer.toString(SecConst.ALLCAS)+';'+Integer.toString(caid));
            profile.setValue(EndEntityProfile.DEFAULTCA, 0, Integer.toString(caid)); 
            eeProfileSession.addEndEntityProfile(admin, profilename, profile);
            EndEntityProfile prof = eeProfileSession.getEndEntityProfile(profilename);
            Collection<String> availcas = prof.getAvailableCAs();
            assertEquals("There should be two available CA in the profile: "+availcas, 2, availcas.size());

            // Start the tests
            // Export the profiles
            caExportProfilesCommand.execute(CAEXPORTPROFILES_ARGS);

            // Import profiles without deleting the old, the import should be ignored
            caImportProfilesCommand.execute(CAIMPORTPROFILES_ARGS);
            prof = eeProfileSession.getEndEntityProfile(profilename);
            assertNotNull(prof);
            availcas = prof.getAvailableCAs();
            assertEquals("There should be two available CA in the profile: "+availcas, 2, availcas.size());
            assertTrue("EE profile "+caid+" should exist", availcas.contains(Integer.toString(caid)));
            assertTrue("EE profile ANYCA should exist", availcas.contains(Integer.toString(SecConst.ALLCAS)));
            assertEquals("DefaultCA should be our test CA", caid, prof.getDefaultCA());

            // Import profiles again, after removing the profile, should be identical
            eeProfileSession.removeEndEntityProfile(admin, profilename);
            caImportProfilesCommand.execute(CAIMPORTPROFILES_ARGS);
            prof = eeProfileSession.getEndEntityProfile(profilename);
            assertNotNull(prof);
            availcas = prof.getAvailableCAs();
            assertEquals("There should be two available CA in the profile: "+availcas, 2, availcas.size());
            assertTrue("EE profile "+caid+" should exist", availcas.contains(Integer.toString(caid)));
            assertTrue("EE profile ANYCA should exist", availcas.contains(Integer.toString(SecConst.ALLCAS)));
            assertEquals("DefaultCA should be our test CA", caid, prof.getDefaultCA());

            // Now remove the CA and import the profile again, the removed CA id should be removed from the profile
            eeProfileSession.removeEndEntityProfile(admin, profilename);
            caSession.removeCA(admin, caid);
            prof = eeProfileSession.getEndEntityProfile(profilename);
            assertNull(prof);
            caImportProfilesCommand.execute(CAIMPORTPROFILES_ARGS);
            prof = eeProfileSession.getEndEntityProfile(profilename);
            assertNotNull(prof);
            availcas = prof.getAvailableCAs();
            assertEquals("There should only be one (ANYCA) available CA in the profile: "+availcas, 1, availcas.size());
            assertFalse("EE profile "+caid+" should not exist", availcas.contains(Integer.toString(caid)));
            assertTrue("EE profile ANYCA should exist", availcas.contains(Integer.toString(SecConst.ALLCAS)));
            assertEquals("DefaultCA should not be our test CA", SecConst.ALLCAS, prof.getDefaultCA());
        } finally {
            eeProfileSession.removeEndEntityProfile(admin, profilename);
            caSession.removeCA(admin, caid);
            CryptoTokenTestUtils.removeCryptoToken(admin, cryptoTokenId);
        }
    }
}
