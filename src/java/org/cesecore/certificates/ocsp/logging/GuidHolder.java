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
package org.cesecore.certificates.ocsp.logging;

import org.cesecore.util.GUIDGenerator;

/**
 * Keeps track of a GUID which identifies this instance.
 * 
 * @version $Id$
 * 
 */
public enum GuidHolder {
    INSTANCE;

    private GuidHolder() {
        guid = GUIDGenerator.generateGUID(this);
    }

    public String getGlobalUid() {
        return guid;
    }

    private final String guid;

}
