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
package org.ejbca.core.model.approval.profile;

import java.util.Collection;
import java.util.HashMap;
import java.util.Map;
import java.util.ServiceLoader;

/**
 * Reads in the implementations of the ApprovalProfile interface. Mainly used by GUI and CLI to list the available types of approvals. 
 * 
 * @version $Id$
 *
 */
public enum ApprovalProfilesFactory {
    INSTANCE;

    private Map<String, ApprovalProfile> identifierToImplementationMap = new HashMap<>();

    private ApprovalProfilesFactory() {
        ServiceLoader<ApprovalProfile> svcloader = ServiceLoader.load(ApprovalProfile.class);
        for(ApprovalProfile type : svcloader) {
            type.initialize();
            identifierToImplementationMap.put(type.getApprovalProfileTypeIdentifier(), type);
        }
    }
    
    public Collection<ApprovalProfile> getAllImplementations() {
        return identifierToImplementationMap.values();
    }
    
    public ApprovalProfile getArcheType(String identifier) {
        return identifierToImplementationMap.get(identifier).clone();
    }
    
   
}
