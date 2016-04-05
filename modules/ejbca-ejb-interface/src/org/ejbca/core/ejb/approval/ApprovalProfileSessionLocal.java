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
import java.util.Map;

import javax.ejb.Local;

import org.ejbca.core.model.approval.ApprovalProfile;

@Local
public interface ApprovalProfileSessionLocal extends ApprovalProfileSession {

    /**
     * @return a collection of all existing approval profiles.
     */
    Map<Integer, ApprovalProfile> getAllApprovalProfiles();
    
    Collection<ApprovalProfile> getApprovalProfilesList();
}
