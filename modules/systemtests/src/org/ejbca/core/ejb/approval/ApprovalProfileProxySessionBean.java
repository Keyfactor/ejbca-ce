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
package org.ejbca.core.ejb.approval;

import java.util.List;

import jakarta.ejb.EJB;
import jakarta.ejb.Stateless;
import jakarta.ejb.TransactionAttribute;
import jakarta.ejb.TransactionAttributeType;

import org.cesecore.profiles.ProfileData;

/**
 *
 */
@Stateless
@TransactionAttribute(TransactionAttributeType.SUPPORTS)
public class ApprovalProfileProxySessionBean implements ApprovalProfileProxySessionRemote {

    @EJB
    private ApprovalProfileSessionLocal approvalProfileSession;
    
    @Override
    public List<ProfileData> findByApprovalProfileName(String profileName) {
        return approvalProfileSession.findByApprovalProfileName(profileName);
    }

}
