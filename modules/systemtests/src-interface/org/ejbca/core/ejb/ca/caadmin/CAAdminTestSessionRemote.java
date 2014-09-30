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

package org.ejbca.core.ejb.ca.caadmin;

import java.io.UnsupportedEncodingException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.Certificate;

import javax.ejb.Remote;

import org.cesecore.certificates.ca.CADoesntExistsException;
import org.cesecore.keys.token.CryptoTokenOfflineException;
import org.cesecore.keys.token.IllegalCryptoTokenException;

@Remote
public interface CAAdminTestSessionRemote {

    /**
     * Retrieve fingerprint for all keys as a String. Used for testing.
     * 
     * @param caname the name of the CA whose fingerprint should be retrieved.
     */
    public String getKeyFingerPrint(String caname) throws CADoesntExistsException, UnsupportedEncodingException, IllegalCryptoTokenException, CryptoTokenOfflineException, NoSuchAlgorithmException;
    
    /**
     * Removes only the data of a certificate.
     */
    public void clearCertData(Certificate cert);
}
