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
package org.ejbca.ra;

import com.keyfactor.util.certificate.DnComponents;

/**
 *
 * @author Marcus Lundblad
 */
public class DnComponentsHelper {
    
    // enum to make type selection for populateRequestFields easy and fixed, with good toString() value for debug log
    public enum RequestFieldType {
        DN,
        AN,
        DIRATTR
    }

    /**
     * Get DN ID from subject name.
     *
     * @param type Request field type (DN name, subject alt name, directory attribute)
     * @param name Subject name
     * @return DN ID
     * @throws IllegalArgumentException if unknown
     */
    public static Integer getDnIdFromTypeAndName(final RequestFieldType type,
                                                 final String name)
        throws IllegalArgumentException {
        switch (type) {
            case DN:
                return DnComponents.getDnIdFromDnName(name);
            case AN: {
                /* populate subject alt name UNIFORMRESOURCEIDENTIFIER
                 * from the CSR as UNIFORMRESOURCEID
                 */
                final String altNameToUse =
                        "UNIFORMRESOURCEIDENTIFIER".equals(name) ?
                        DnComponents.UNIFORMRESOURCEID : name;

                return DnComponents.getDnIdFromAltName(altNameToUse);
            }
            case DIRATTR:
                return DnComponents.getDnIdFromDirAttr(name);
            default:
                throw new IllegalArgumentException("Unknown request field type: " +
                                                   type.name());
        }
    }
}
