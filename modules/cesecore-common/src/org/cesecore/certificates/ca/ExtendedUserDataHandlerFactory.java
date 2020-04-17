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
package org.cesecore.certificates.ca;

import java.util.Collection;
import java.util.HashMap;
import java.util.Map;
import java.util.ServiceLoader;

/**
 * Factory singleton for delivering all found implementations of the ExtendedUserDataHandler interface
 * 
 * @version $Id$
 *
 */
public enum ExtendedUserDataHandlerFactory {
    INSTANCE;

    private Map<String, ExtendedUserDataHandler> identifierToImplementationMap = new HashMap<>();
    
    private ExtendedUserDataHandlerFactory() {
        ServiceLoader<ExtendedUserDataHandler> svcloader = ServiceLoader.load(ExtendedUserDataHandler.class);
        for(ExtendedUserDataHandler type : svcloader) {
            identifierToImplementationMap.put(type.getReadableName(), type);
        }
    }
    
    public Collection<ExtendedUserDataHandler> getAllImplementations() {
        return identifierToImplementationMap.values();
    }

}
