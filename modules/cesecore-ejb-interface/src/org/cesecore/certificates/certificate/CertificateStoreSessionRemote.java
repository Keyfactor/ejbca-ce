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

import java.security.cert.Certificate;
import java.security.cert.CertificateParsingException;

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
     * @deprecated Not all types of certificates can be serialized (e.g. Brainpool certificates). Use the overloaded version that takes a BASE64 encoded string instead.
     * 
     * @see CertificateStoreSessionRemote#storeCertificateRemote(AuthenticationToken, String, String, String, int, int, int, String, long)
     */
    void storeCertificateRemote(AuthenticationToken admin, Certificate incert, String username, String cafp, int status, int type,
            int certificateProfileId, String tag, long updateTime) throws AuthorizationDeniedException;

    /**
     * Stores a certificate (remote EJB interface).
     * 
     * @param admin An authentication token to authorize the action
     * @param b64Cert The certificate to be stored, BASE64 encoded.
     * @param cafp Fingerprint (hex) of the CAs certificate.
     * @param username username of end entity owning the certificate.
     * @param status the status from the CertificateConstants.CERT_ constants
     * @param type Type of certificate (CERTTYPE_ENDENTITY etc from CertificateConstants).
     * @param certificateProfileId the certificate profile id this cert was issued under
     * @param tag a custom string tagging this certificate for some purpose
     * @param updateTime epoch millis to use as last update time of the stored object
     *
     * @throws AuthorizationDeniedException if admin was not authorized to store certificate in database
     */
    void storeCertificateRemote(AuthenticationToken admin, String b64Cert, String username, String cafp, int status, int type,
            int certificateProfileId, String tag, long updateTime) throws AuthorizationDeniedException, CertificateParsingException;

}
