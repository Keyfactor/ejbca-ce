/*************************************************************************
 *                                                                       *
 *  CESeCore: CE Security Core                                           *
 *                                                                       *
 *  This software is free software; you can redistribute it and/or       *
 *  modify it under the terms of the GNU Lesser General Public           *
 *  License as published by the Free Software Foundation; either         *
 *  version 2.1 of the License, or any later version.                    *
 *                                                                       *
 *  See terms of license at gnu.org.                                     *
 *                                                                       *
 *************************************************************************/
package org.cesecore.certificates.certificate;

import javax.ejb.Remote;

import org.cesecore.authentication.tokens.AuthenticationToken;
import org.cesecore.authorization.AuthorizationDeniedException;

/**
 * Remote interface for CertificateStoreSession.
 * 
 * @version $Id$
 */
@Remote
public interface CertificateStoreSessionRemote extends CertificateStoreSession {

    /**
     * Stores a certificate (remote EJB interface).
     * 
     * @param admin An authentication token to authorize the action
     * @param cert Wrapper of the certificate to be stored. Use {@link org.cesecore.util.EJBTools#wrap} to construct to the wrapper.
     * @param cafp Fingerprint (hex) of the CAs certificate.
     * @param username username of end entity owning the certificate.
     * @param status the status from the CertificateConstants.CERT_ constants
     * @param type Type of certificate (CERTTYPE_ENDENTITY etc from CertificateConstants).
     * @param certificateProfileId the certificate profile id this cert was issued under
     * @param endEntityProfileId the end entity profile id the cert was issued under
     * @param tag a custom string tagging this certificate for some purpose
     * @param updateTime epoch millis to use as last update time of the stored object
     *
     * @throws AuthorizationDeniedException if admin was not authorized to store certificate in database
     */
    void storeCertificateRemote(AuthenticationToken admin, CertificateWrapper cert, String username, String cafp, int status, int type,
            int certificateProfileId, int endEntityProfileId, String tag, long updateTime) throws AuthorizationDeniedException;

    /**
     * Finds a certificate by fingerprint (remote EJB interface, supports unnamed ECC and Brainpool)
     * @param fingerprint Fingerprint of certificate
     * @return Wrapped certificate, or null if no certificate was found. Use {@link org.cesecore.util.EJBTools#unwrap} to extract the certificate.
     */
    CertificateWrapper findCertificateByFingerprintRemote(String fingerprint);

}
