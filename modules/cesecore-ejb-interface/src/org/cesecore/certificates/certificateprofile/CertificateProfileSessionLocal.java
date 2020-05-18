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
package org.cesecore.certificates.certificateprofile;

import java.util.Map;

import javax.ejb.Local;

import org.cesecore.authentication.tokens.AuthenticationToken;

/**
 * @version $Id$
 */
@Local
public interface CertificateProfileSessionLocal extends CertificateProfileSession {

    /**
     * 
     * @return a collection of all existing certificate profiles.
     */
    Map<Integer, CertificateProfile> getAllCertificateProfiles();
    
    /**
     * Checks authorization to profiles. Only profiles that refer to CA's that the authentication token is 
     * authorized to will be OK. Also checks the passed in extra resources. 
     * Does this in a single call to authorizationSession to keep it efficient
     * 
     * @param authenticationToken Administrator performing the operation
     * @param profile Certificate Profile that we want to check authorization for
     * @param logging if we should log access or not
     * @param resources, additional resources to check, for example StandardRules.CERTIFICATEPROFILEEDIT.resource()
     * @return true if authorized to the profile and the resources
     */
    boolean authorizedToProfileWithResource(
            final AuthenticationToken authenticationToken,
            final CertificateProfile profile,
            final boolean logging,
            final String... resources);

}
