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

import junit.framework.TestCase;

import org.apache.log4j.Logger;
import org.cesecore.authentication.tokens.AlwaysAllowLocalAuthenticationToken;
import org.cesecore.authentication.tokens.AuthenticationToken;
import org.cesecore.authentication.tokens.UsernamePrincipal;
import org.ejbca.core.model.hardtoken.HardTokenIssuer;
import org.ejbca.core.model.hardtoken.HardTokenIssuerData;
import org.ejbca.util.InterfaceCache;


/**
 * Tests the Hard Token Issuer entity bean.
 *
 * @version $Id$
 */
public class HardTokenIssuerTest extends TestCase {
    private static Logger log = Logger.getLogger(HardTokenIssuerTest.class);
    
    private HardTokenSessionRemote hardTokenSession = InterfaceCache.getHardTokenSession();

    private static final AuthenticationToken admin = new AlwaysAllowLocalAuthenticationToken(new UsernamePrincipal("SYSTEMTEST"));

    /**
     * Creates a new TestHardTokenIssuer object.
     *
     * @param name name
     */
    public HardTokenIssuerTest(String name) {
        super(name);
    }

    public void setUp() throws Exception {
    }

    public void tearDown() throws Exception {
    }

    /**
     * adds a issuer to the database
     *
     * @throws Exception error
     */
    public void test01AddHardTokenIssuer() throws Exception {
        log.trace(">test01AddHardTokenIssuer()");
        boolean ret = false;
        HardTokenIssuer issuer = new HardTokenIssuer();
        issuer.setDescription("TEST");
        ret = hardTokenSession.addHardTokenIssuer(admin, "TEST", 3, issuer);
        assertTrue("Creating Hard Token Issuer failed", ret);
        log.trace("<test01AddHardTokenIssuer()");
    }

    /**
     * renames issuer
     *
     * @throws Exception error
     */
    public void test02RenameHardTokenIssuer() throws Exception {
        log.trace(">test02RenameHardTokenIssuer()");

        boolean ret = false;
        ret = hardTokenSession.renameHardTokenIssuer(admin, "TEST", "TEST2", 4);
        assertTrue("Renaming Hard Token Issuer failed", ret);

        log.trace("<test02RenameHardTokenIssuer()");
    }

    /**
     * clones issuer
     *
     * @throws Exception error
     */
    public void test03CloneHardTokenIssuer() throws Exception {
        log.trace(">test03CloneHardTokenIssuer()");

        boolean ret = false;
        ret = hardTokenSession.cloneHardTokenIssuer(admin, "TEST2", "TEST", 4);

        assertTrue("Cloning Certificate Profile failed", ret);

        log.trace("<test03CloneHardTokenIssuer()");
    }


    /**
     * edits issuer
     *
     * @throws Exception error
     */
    public void test04EditHardTokenIssuer() throws Exception {
        log.trace(">test04EditHardTokenIssuer()");
        boolean ret = false;
        HardTokenIssuerData issuerdata = hardTokenSession.getHardTokenIssuerData(admin, "TEST");
        assertTrue("Retrieving HardTokenIssuer failed", issuerdata.getHardTokenIssuer().getDescription().equals("TEST"));
        issuerdata.getHardTokenIssuer().setDescription("TEST2");
        ret = hardTokenSession.changeHardTokenIssuer(admin, "TEST", issuerdata.getHardTokenIssuer());
        assertTrue("Editing HardTokenIssuer failed", ret);
        log.trace("<test04EditHardTokenIssuer()");
    }

    /**
     * removes all profiles
     *
     * @throws Exception error
     */
    public void test05removeHardTokenIssuers() throws Exception {
        log.trace(">test05removeHardTokenIssuers()");
        boolean ret = false;
        try {
            hardTokenSession.removeHardTokenIssuer(admin, "TEST");
            hardTokenSession.removeHardTokenIssuer(admin, "TEST2");
            ret = true;
        } catch (Exception pee) {
        }
        assertTrue("Removing Certificate Profile failed", ret);
        log.trace("<test05removeHardTokenIssuers()");
    }


}
