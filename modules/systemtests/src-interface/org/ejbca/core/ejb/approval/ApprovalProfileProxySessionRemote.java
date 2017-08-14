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

import javax.ejb.Remote;

import org.cesecore.profiles.ProfileData;

/**
 * @version $Id$
 *
 */
@Remote
public interface ApprovalProfileProxySessionRemote {

    /**
     * @return the found entity instance or null if the entity does not exist
     */
    List<ProfileData> findByApprovalProfileName(String profileName);
    
}
