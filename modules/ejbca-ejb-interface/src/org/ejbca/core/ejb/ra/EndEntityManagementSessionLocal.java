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

import java.util.Collection;
import java.util.List;

import javax.ejb.Local;

import org.cesecore.authentication.tokens.AuthenticationToken;
import org.cesecore.authorization.AuthorizationDeniedException;
import org.cesecore.certificates.endentity.EndEntityInformation;
import org.ejbca.core.model.approval.ApprovalException;
import org.ejbca.core.model.approval.WaitingForApprovalException;
import org.ejbca.core.model.ra.CustomFieldException;

/**
 * Local interface for EndEntityManagementSession.
 */
@Local
public interface EndEntityManagementSessionLocal extends EndEntityManagementSession {

    /**
     * Validates the name and DN in an end entity and canonicalizes/strips
     * the attributes. This method is called by addUser.
     * 
     * @return a copy of endEntity with the canonicalized changes. Does not modify its parameter.
     * 
     * @throws CustomFieldException if if the end entity was not validated by a locally defined field validator
     * 
     */
    EndEntityInformation canonicalizeUser(final EndEntityInformation endEntity) throws CustomFieldException;
    
    /**
     * Finds all users, limited by the maximum query count defined in the global configuration.
     * 
     * @return Collection of EndEntityInformation
     */
    Collection<EndEntityInformation> findAllUsersWithLimit(AuthenticationToken admin);

    /**
     * Methods that checks if a user exists in the database having the given
     * caid. This function is mainly for avoiding desynchronization when a CAs
     * is deleted.
     * 
     * @param caid the id of CA to look for.
     * @return true if caid exists in UserData table.
     */
    boolean checkForCAId(int caid);

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
     * Methods that checks if a user exists in the database having the given
     * HardTokenProfile id. This function is mainly for avoiding
     * desynchronization when a HardTokenProfile is deleted.
     * 
     * @param profileid of HardTokenProfile to look for.
     * @return true if profileid exists in UserData table.
     */
    boolean checkForHardTokenProfileId(int profileid);

    /**
     * Cleans the certificate serial number from the user data. Should be called
     * after the data has been used.
     * @throws NoSuchEndEntityException if no end entity was found
     * 
     */
    void cleanUserCertDataSN(EndEntityInformation data) throws NoSuchEndEntityException;

    /**
     * Removes the certificate serial number from the user data.
     * @param username the unique username.
     * @throws NoSuchEndEntityException if the end entity was not found
     */
    void cleanUserCertDataSN(String username) throws ApprovalException, WaitingForApprovalException, NoSuchEndEntityException;

    /**
     * Decreases (the optional) request counter by 1, until it reaches 0.
     * Returns the new value. If the value is already 0, -1 is returned, but the
     * -1 is not stored in the database. Also sets status of user to generated
     * once the request counter reaches zero.
     * 
     * @param username the unique username.
     * @param status the new status, from 'UserData'.
     * @throws NoSuchEndEntityException if user does not exist
     */
    int decRequestCounter(String username) throws NoSuchEndEntityException, ApprovalException, WaitingForApprovalException;
        
    /**
     * Changes the CAId of the given end-entity. Intended to be used when an uninitialized CA's subject DN and CAId is changed
     * (CAs can be in the uninitialized state when they have been imported from a statedump).
     * 
     * @param admin Authentication token
     * @param username End-entity to change CAId of
     * @param newCAId CA id to change to.
     */
    void updateCAId(final AuthenticationToken admin, final String username, int newCAId) throws AuthorizationDeniedException, NoSuchEndEntityException;

    /**
     * Like {@link EndEntityManagementSession#findAllUsersByCaId}, but performs no auth check.
     */
    Collection<EndEntityInformation> findAllUsersByCaIdNoAuth(int caid);

}
