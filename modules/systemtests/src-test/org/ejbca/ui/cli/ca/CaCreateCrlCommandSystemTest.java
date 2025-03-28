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

import java.text.ParseException;
import java.text.SimpleDateFormat;

import org.cesecore.CaTestUtils;
import org.cesecore.authentication.tokens.AuthenticationToken;
import org.cesecore.certificates.ca.CaSessionRemote;
import org.cesecore.certificates.ca.X509CA;
import org.cesecore.certificates.certificate.CertificateConstants;
import org.cesecore.certificates.crl.CRLInfo;
import org.cesecore.certificates.crl.CrlStoreSessionRemote;
import org.cesecore.mock.authentication.tokens.TestAlwaysAllowLocalAuthenticationToken;
import org.cesecore.util.EjbRemoteHelper;
import org.junit.After;
import org.junit.Before;
import org.junit.BeforeClass;
import org.junit.Test;

import com.keyfactor.util.CryptoProviderTools;

/**
 * @version $Id$
 *
 */
public class CaCreateCrlCommandSystemTest {

    private static final String CA_NAME = "CaCreateCrlCommandSystemTest";
    private static final String CA_DN = "CN=" + CA_NAME;
    
    private final CaCreateCrlCommand command = new CaCreateCrlCommand();
    
    private final CaSessionRemote caSession = EjbRemoteHelper.INSTANCE.getRemoteSession(CaSessionRemote.class);
    private final CrlStoreSessionRemote crlStoreSession = EjbRemoteHelper.INSTANCE.getRemoteSession(CrlStoreSessionRemote.class);

    private X509CA ca;
    private final AuthenticationToken authenticationToken = new TestAlwaysAllowLocalAuthenticationToken(
            CaChangeCertProfileCommand.class.getSimpleName());

    @BeforeClass
    public static void beforeClass() throws Exception {
        CryptoProviderTools.installBCProviderIfNotAvailable();
    }

    @Before
    public void setup() throws Exception {
        ca = CaTestUtils.createTestX509CA(CA_DN, null, false);
        caSession.addCA(authenticationToken, ca);
    }

    @After
    public void tearDown() throws Exception {
        if (ca != null) {
            CaTestUtils.removeCa(authenticationToken, ca.getCAInfo());
        }
    }

    @Test
    public void testCommand() {
        CRLInfo oldCrl = crlStoreSession.getLastCRLInfo(CA_DN, CertificateConstants.NO_CRL_PARTITION, false);
        String[] args = new String[] { CA_NAME };
        command.execute(args);
        assertFalse("No CRL was produced", crlStoreSession.getLastCRLInfo(CA_DN, CertificateConstants.NO_CRL_PARTITION, false).equals(oldCrl));
    }

    @Test
    public void testFutureValidityTime() throws ParseException {
        final String dateAsString = "25000101070000";
        final SimpleDateFormat format = new SimpleDateFormat("yyyyMMddHHmmss");
        CRLInfo oldCrl = crlStoreSession.getLastCRLInfo(CA_DN, CertificateConstants.NO_CRL_PARTITION, false);
        String[] args = new String[] { CA_NAME, "--updateDate="+dateAsString};
        command.execute(args);
        CRLInfo newCrl = crlStoreSession.getLastCRLInfo(CA_DN, CertificateConstants.NO_CRL_PARTITION, false);
        assertFalse("No CRL was produced", newCrl.equals(oldCrl));
        assertEquals("CRL was not given desired future date.", format.parse(dateAsString), newCrl.getCreateDate());
    }
    
    // TODO Add test of Partitioned CRLs (ECA-7961)
}
