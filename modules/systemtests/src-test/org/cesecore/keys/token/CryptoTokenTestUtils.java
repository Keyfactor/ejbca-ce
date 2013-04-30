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
package org.cesecore.keys.token;

import org.cesecore.authentication.tokens.AuthenticationToken;
import org.cesecore.authorization.AuthorizationDeniedException;
import org.cesecore.certificates.ca.CADoesntExistsException;
import org.cesecore.certificates.ca.CaSessionRemote;
import org.cesecore.certificates.ca.CaSessionTest;
import org.cesecore.certificates.ca.X509CA;
import org.cesecore.util.EjbRemoteHelper;

/**
 * @version $Id$
 *
 */
public class CryptoTokenTestUtils {

    public static X509CA createTestCA(AuthenticationToken authenticationToken, String dN) throws Exception {
        CaSessionRemote caSession = EjbRemoteHelper.INSTANCE.getRemoteSession(CaSessionRemote.class);
        CryptoTokenManagementSessionRemote cryptoTokenManagementSession = EjbRemoteHelper.INSTANCE.getRemoteSession(CryptoTokenManagementSessionRemote.class);
        
        X509CA x509ca = CaSessionTest.createTestX509CA(dN, "foo123".toCharArray(), false);
        // Remove any lingering test CA before starting the tests
        try {
            final int oldCaCryptoTokenId = caSession.getCAInfo(authenticationToken, x509ca.getCAId()).getCAToken().getCryptoTokenId();
            cryptoTokenManagementSession.deleteCryptoToken(authenticationToken, oldCaCryptoTokenId);
        } catch (CADoesntExistsException e) {
            // Ok. The old test run cleaned up everything properly.
        }
        caSession.removeCA(authenticationToken, x509ca.getCAId());
        // Now add the test CA so it is available in the tests
        caSession.addCA(authenticationToken, x509ca);
        return x509ca;
    }
    
    public static int createCryptoToken(AuthenticationToken authenticationToken, String cryptoTokenName) throws AuthorizationDeniedException,
            CryptoTokenOfflineException, CryptoTokenAuthenticationFailedException, CryptoTokenNameInUseException {
        CryptoTokenManagementSessionRemote cryptoTokenManagementSession = EjbRemoteHelper.INSTANCE
                .getRemoteSession(CryptoTokenManagementSessionRemote.class);
        // Remove any old CryptoToken created by this setup
        final Integer oldCryptoTokenId = cryptoTokenManagementSession.getIdFromName(cryptoTokenName);
        if (oldCryptoTokenId != null) {
            cryptoTokenManagementSession.deleteCryptoToken(authenticationToken, oldCryptoTokenId.intValue());
        }
        // Create one additional CryptoToken to use from the tests below
        return cryptoTokenManagementSession.createCryptoToken(authenticationToken, cryptoTokenName, SoftCryptoToken.class.getName(), null, null,
                "foo123".toCharArray());
    }
    
}
