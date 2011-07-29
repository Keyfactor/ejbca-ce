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
package org.ejbca.core.ejb.audit.enums;

import org.cesecore.audit.enums.EventType;

/**
 * EJBCA specific event types.
 * 
 * @version $Id$
 * 
 */
public enum EjbcaEventTypes implements EventType {
    PUBLISHER_CHANGE,
    PUBLISHER_CLONE,
    PUBLISHER_CREATION,
    PUBLISHER_REMOVAL,
    PUBLISHER_RENAME,
    PUBLISHER_STORE_CERTIFICATE,
    PUBLISHER_STORE_CRL,
    PUBLISHER_TEST_CONNECTION;

    @Override
    public boolean equals(EventType value) {
        if (value == null) {
            return false;
        }
        return this.toString().equals(value.toString());
    }

}
