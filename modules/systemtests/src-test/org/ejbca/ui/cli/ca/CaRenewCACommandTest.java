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
import static org.junit.Assert.assertTrue;

import java.security.cert.X509Certificate;
import java.util.Arrays;
import java.util.Calendar;
import java.util.TimeZone;

import org.apache.log4j.Logger;
import org.cesecore.authentication.tokens.AuthenticationToken;
import org.cesecore.authentication.tokens.UsernamePrincipal;
import org.cesecore.certificates.ca.CaSessionRemote;
import org.cesecore.certificates.ca.X509CAInfo;
import org.cesecore.mock.authentication.tokens.TestAlwaysAllowLocalAuthenticationToken;
import org.cesecore.util.EjbRemoteHelper;
import org.ejbca.core.ejb.ca.CaTestCase;
import org.ejbca.ui.cli.infrastructure.command.CommandResult;
import org.junit.After;
import org.junit.Before;
import org.junit.Test;

/**
 * Tests the CaRenewCACommand.
 *
 * @version $Id$
 */
public class CaRenewCACommandTest extends CaTestCase {
    
	/** Logger for this class. */
	private static final Logger LOG = Logger.getLogger(CaRenewCACommandTest.class);
	
	private static final AuthenticationToken internalAdmin = new TestAlwaysAllowLocalAuthenticationToken(new UsernamePrincipal("CaRenewCACommandTest"));
    
	private static final String CA_NAME = "TEST";

	private X509Certificate orgCert;

	@Before
    public void setUp() throws Exception {
        super.setUp();
    	final X509CAInfo info = (X509CAInfo) EjbRemoteHelper.INSTANCE.getRemoteSession(CaSessionRemote.class).getCAInfo(internalAdmin, CA_NAME);
    	orgCert = (X509Certificate) info.getCertificateChain().iterator().next();
    }

    @After
    public void tearDown() throws Exception {
        super.tearDown();
    }

    @Override
    public String getRoleName() {
        return this.getClass().getSimpleName(); 
    }

    /**
     * Tests renewal of CA using CLI for the old key. 
     * @throws Exception in case of error
     */
    @Test
    public void test01renewCAwithSameKeys() throws Exception {
        LOG.trace(">test01renewCAwithSameKeys()");

        final CaRenewCACommand command = new CaRenewCACommand();
        assertEquals(CommandResult.SUCCESS, command.execute(new String[]{ CA_NAME, "foo123"}));
        
        final X509CAInfo newinfo = (X509CAInfo) EjbRemoteHelper.INSTANCE.getRemoteSession(CaSessionRemote.class).getCAInfo(internalAdmin, CA_NAME);
        final X509Certificate newcertsamekeys = (X509Certificate) newinfo.getCertificateChain().iterator().next();
        
        assertTrue("new serial number", !orgCert.getSerialNumber().equals(newcertsamekeys.getSerialNumber()));
        
        final byte[] orgkey = orgCert.getPublicKey().getEncoded();
        final byte[] samekey = newcertsamekeys.getPublicKey().getEncoded();
        assertTrue("same key", Arrays.equals(orgkey, samekey));
        
        // The new certificate should have a validity greater than the old cert
        assertTrue("newcertsamekeys.getNotAfter: " + newcertsamekeys.getNotAfter()
        		+ " orgcert.getNotAfter: "+orgCert.getNotAfter(), 
        		newcertsamekeys.getNotAfter().after(orgCert.getNotAfter()));
        
        LOG.trace("<test01renewCAwithSameKeys()");
    }
    
    /**
     * Test renewal of the CA using CLI and generating a new key pair.
     * Assumption: the default system keystore password is not changed from foo123
     * @throws Exception in case of error
     */
    @Test
    public void test02renewCAwithNewKeys() throws Exception {
    	LOG.trace(">test02renewCAwithNewKeys()");
    	
    	final CaRenewCACommand command = new CaRenewCACommand();
        command.execute(new String[]{ CA_NAME, "foo123", "-R"});
    	
		final X509CAInfo newinfo2 = (X509CAInfo) EjbRemoteHelper.INSTANCE.getRemoteSession(CaSessionRemote.class).getCAInfo(internalAdmin, CA_NAME);
		final X509Certificate newcertnewkeys = (X509Certificate) newinfo2.getCertificateChain().iterator().next();
		
		assertTrue("new serial number", !orgCert.getSerialNumber().equals(newcertnewkeys.getSerialNumber()));
		
		final byte[] orgkey = orgCert.getPublicKey().getEncoded();
        final byte[] samekey = newcertnewkeys.getPublicKey().getEncoded();
        assertFalse("new key", Arrays.equals(orgkey, samekey));

		LOG.trace(">test02renewCAwithNewKeys()");
    }
    
    /**
     * Tests renewal of CA using CLI for the old key and with a custom notBefore date. 
     *
     * @throws Exception in case of error
     */
    @Test
    public void test03renewCAwithSameKeysAndCustomNotBefore() throws Exception {
        LOG.trace(">test03renewCAwithSameKeysAndCustomNotBefore()");
        
        Calendar cal = Calendar.getInstance();
        cal.set(Calendar.YEAR, 2009);
        cal.set(Calendar.MONTH, 4 - 1);
        cal.set(Calendar.DAY_OF_MONTH, 15);
        cal.set(Calendar.HOUR_OF_DAY, 8);
        cal.set(Calendar.MINUTE, 55);
        cal.set(Calendar.SECOND, 0);
        cal.set(Calendar.MILLISECOND, 0);
        cal.setTimeZone(TimeZone.getTimeZone("GMT+02:00"));
        final String notBefore = "2009-04-15 08:55:00+02:00";
        
        final CaRenewCACommand command = new CaRenewCACommand();
        assertEquals(CommandResult.SUCCESS, command.execute(new String[]{CA_NAME, "foo123", "--notbefore", notBefore}));
        
        final X509CAInfo newinfo = (X509CAInfo) EjbRemoteHelper.INSTANCE.getRemoteSession(CaSessionRemote.class).getCAInfo(internalAdmin, CA_NAME);
        final X509Certificate newcertsamekeys = (X509Certificate) newinfo.getCertificateChain().iterator().next();
        
        assertTrue("No new serial number.", !orgCert.getSerialNumber().equals(newcertsamekeys.getSerialNumber()));
        
        final byte[] orgkey = orgCert.getPublicKey().getEncoded();
        final byte[] samekey = newcertsamekeys.getPublicKey().getEncoded();
        assertTrue("same key", Arrays.equals(orgkey, samekey));
        
        // The new certificate should have the custom notBefore date
        assertEquals(cal.getTime(), newcertsamekeys.getNotBefore());
        
        LOG.trace("<test03renewCAwithSameKeysAndCustomNotBefore()");
    }
    
    /**
     * Test renewal of the CA using CLI and generating a new key pair.
     * Assumption: the default system keystore password is not changed from foo123
     * 
     * @throws Exception in case of error
     */
    @Test
    public void test04renewCAwithNewKeysAndCustomNotBefore() throws Exception {
    	LOG.trace(">test04renewCAwithNewKeysAndCustomNotBefore()");
    	
        Calendar cal = Calendar.getInstance();
        cal.set(Calendar.YEAR, 2009);
        cal.set(Calendar.MONTH, 4 - 1);
        cal.set(Calendar.DAY_OF_MONTH, 15);
        cal.set(Calendar.HOUR_OF_DAY, 8);
        cal.set(Calendar.MINUTE, 55);
        cal.set(Calendar.SECOND, 0);
        cal.set(Calendar.MILLISECOND, 0);
        cal.setTimeZone(TimeZone.getTimeZone("GMT+02:00"));
        final String notBefore = "2009-04-15 08:55:00+02:00";
    	
    	final CaRenewCACommand command = new CaRenewCACommand();
        command.execute(new String[]{ CA_NAME, "foo123", "-R", "--notbefore", notBefore});
    	
		final X509CAInfo newinfo2 = (X509CAInfo) EjbRemoteHelper.INSTANCE.getRemoteSession(CaSessionRemote.class).getCAInfo(internalAdmin, CA_NAME);
		final X509Certificate newcertnewkeys = (X509Certificate) newinfo2.getCertificateChain().iterator().next();
		
		assertTrue("new serial number", !orgCert.getSerialNumber().equals(newcertnewkeys.getSerialNumber()));
		
		final byte[] orgkey = orgCert.getPublicKey().getEncoded();
        final byte[] samekey = newcertnewkeys.getPublicKey().getEncoded();
        assertFalse("new key", Arrays.equals(orgkey, samekey));
        
        // The new certificate should have the custom notBefore date
        assertEquals(cal.getTime(), newcertnewkeys.getNotBefore());

		LOG.trace(">test04renewCAwithNewKeysAndCustomNotBefore()");
    }
    
    /**
     * Tests renewal of CA using CLI for the old key using no
     * optional parameters in the command. 
     * @throws Exception in case of error
     */
    @Test
    public void test05renewCAwithNoOptionalParams() throws Exception {
        LOG.trace(">test05renewCAwithNoOptionalParams()");

        // We want there to be a difference in the issue dates to see 
        // that the new certificate got a new date, so we sleep for
        // a while to be sure the dates will be different.
        Thread.sleep(2000);
        
        final CaRenewCACommand command = new CaRenewCACommand();
        command.execute(new String[]{ CA_NAME});
        
        final X509CAInfo newinfo = (X509CAInfo) EjbRemoteHelper.INSTANCE.getRemoteSession(CaSessionRemote.class).getCAInfo(internalAdmin, CA_NAME);
        final X509Certificate newcertsamekeys = (X509Certificate) newinfo.getCertificateChain().iterator().next();
        
        assertTrue("new serial number", !orgCert.getSerialNumber().equals(newcertsamekeys.getSerialNumber()));
        
        final byte[] orgkey = orgCert.getPublicKey().getEncoded();
        final byte[] samekey = newcertsamekeys.getPublicKey().getEncoded();
        assertTrue("same key", Arrays.equals(orgkey, samekey));
        
        // The new certificate should have a validity greater than the old cert
        assertTrue("newcertsamekeys.getNotAfter: " + newcertsamekeys.getNotAfter()
        		+ " orgcert.getNotAfter: "+orgCert.getNotAfter(), 
        		newcertsamekeys.getNotAfter().after(orgCert.getNotAfter()));
        
        LOG.trace("<test05renewCAwithNoOptionalParams()");
    }

}
