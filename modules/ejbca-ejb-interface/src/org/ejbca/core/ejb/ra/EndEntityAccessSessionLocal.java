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
package org.ejbca.core.ejb.ra;

import java.util.AbstractMap;
import java.util.Collection;
import java.util.List;

import javax.ejb.Local;

import org.cesecore.authentication.tokens.AuthenticationToken;
import org.cesecore.certificates.endentity.EndEntityInformation;
import org.ejbca.core.model.ra.NotFoundException;
import org.ejbca.util.crypto.SupportedPasswordHashAlgorithm;

/**
 * @version $Id$
 *
 */
@Local
public interface EndEntityAccessSessionLocal extends EndEntityAccessSession {

    /**
     * Finds a user by username, performs no authorization
     * 
     * @return EndEntityInformation or null if the user is not found.
     */
    EndEntityInformation findUser(String username);
    
    /**
     * Using some heuristics and tarot cards, returns which algorithm and method that's been used to hash this user's password.
     * 
     * @param username the user name of the sought user.
     * @return the password and algorithm for the sought user. If algorithm is hashed, so will the password be, otherwise cleartext. Null if user was not found.
     * @throws NotFoundException 
     */
    AbstractMap.SimpleEntry<String, SupportedPasswordHashAlgorithm> getPasswordAndHashAlgorithmForUser(String username) throws NotFoundException;
    
    /**
     * Method that checks if a user exists in the database having the given
     * CertificateProfile id. This function is mainly for avoiding
     * desynchronization when a CertificateProfile is deleted.
     * 
     * @param certificateprofileid the id of CertificateProfile to look for.
     * @return a list of end entities using the certificate profile
     */
     List<String> findByCertificateProfileId(int certificateprofileid);
    
    /**
     * Methods that returns a list of users in the database having the given
     * EndEntityProfile id. This function is mainly for avoiding
     * desynchronization when a end entity profile is deleted.
     * 
     * @param endentityprofileid the id of end entity profile to look for
     * @return a list of UserDatas with the End Entity Profile
     */
    List<UserData> findByEndEntityProfileId(int endentityprofileid);
   
    
    /**
     * 
     * @return a count of UserDatas with the specified CA.
     */
    long countByCaId(int caId);
    
    /** @return return a count of UserDatas with the specified Certificate Profile. */
    long countByCertificateProfileId(int certificateProfileId);
    
    /** @return return a count of UserDatas with tokenType TOKEN_HARD_DEFAULT and status NEW or KEYRECOVERY. */
    long countByHardTokenIssuerId(int hardTokenIssuerId);
    
    /** @return return a count of UserDatas with tokenType TOKEN_HARD_DEFAULT and status NEW or KEYRECOVERY. */
    long countNewOrKeyrecByHardTokenIssuerId(int hardTokenIssuerId);
    
    /** @return the found entity instance or null if the entity does not exist */
    UserData findByUsername(String username);
    
    /** @return return a List<UserData> with tokenType TOKEN_HARD_DEFAULT and status NEW or KEYRECOVERY. */
    List<UserData> findNewOrKeyrecByHardTokenIssuerId(int hardTokenIssuerId, int maxResults);
    
    /** @return a list of subjectDNs that contain SN=serialnumber* for a CA and excludes a username. */
    List<String> findSubjectDNsByCaIdAndNotUsername(final int caId, final String username, final String serialnumber);
    
    /**
     * Like {@link EndEntityManagementSession#findAllUsersByCaId}, but performs no auth check.
     */
    Collection<EndEntityInformation> findAllUsersByCaIdNoAuth(int caid);
    
    /**
     * Finds all users, limited by the maximum query count defined in the global configuration.
     * 
     * @return Collection of EndEntityInformation
     */
    Collection<EndEntityInformation> findAllUsersWithLimit(AuthenticationToken admin);
}
