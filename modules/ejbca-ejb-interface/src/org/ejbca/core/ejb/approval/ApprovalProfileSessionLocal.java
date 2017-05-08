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
package org.ejbca.core.ejb.approval;

import java.util.Collection;
import java.util.List;
import java.util.Map;

import javax.ejb.Local;

import org.cesecore.certificates.ca.ApprovalRequestType;
import org.cesecore.certificates.ca.CAInfo;
import org.cesecore.certificates.certificateprofile.CertificateProfile;
import org.ejbca.core.ejb.profiles.ProfileData;
import org.ejbca.core.model.approval.profile.ApprovalProfile;

/**
 * Session to access approval profiles locally
 * 
 * @version $Id$
 */
@Local
public interface ApprovalProfileSessionLocal extends ApprovalProfileSession {
    
    /** @return the found entity instance or null if the entity does not exist */
    ProfileData findById(int id);
    
    /**
     * @return the found entity instances or an empty list. 
     */
    List<ProfileData> findByNameAndType(final String name, final String type);
    
    /**
     * @return the found entity instance or null if the entity does not exist
     */
    List<ProfileData> findByApprovalProfileName(String profileName);
    
    /** @return return all approval profiles  as a List. */
    List<ProfileData> findAllApprovalProfiles();
    
    /**
     * @return a map of all existing approval profiles.
     */
    Map<Integer, ApprovalProfile> getAllApprovalProfiles();
    
    /**
     * @return a list of all existing approval profiles
     */
    Collection<ApprovalProfile> getApprovalProfilesList();
    
    /**
     * Returns the appropriate approval profile for the given action, where any approval profile defined in the certificate profile trumps any 
     * define in the CA
     * 
     * @param action an approval action
     * @param cainfo a CA information object
     * @param certProfile a certificate profile
     * @return the most appropriate profile for the action, or null if none was found.
     */
    ApprovalProfile getApprovalProfileForAction(final ApprovalRequestType action, final CAInfo cainfo, final CertificateProfile certProfile);
}
