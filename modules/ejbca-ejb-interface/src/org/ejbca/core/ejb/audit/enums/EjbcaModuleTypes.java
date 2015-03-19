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
package org.ejbca.core.ejb.audit.enums;

import org.cesecore.audit.enums.ModuleType;

/**
 * EJBCA specific module types.
 * 
 * @version $Id$
 */
public enum EjbcaModuleTypes implements ModuleType {
    /** Registration Authority module. */
    RA,
    /** (Client) hardware token management module. */
    HARDTOKEN,
    /** Key recovery module. */
    KEYRECOVERY,
    /** Approval module. */
    APPROVAL,
    /** Publisher module. */
    PUBLISHER,
    /** EJBCA background service module. */
    SERVICE,
    /** External module. */
    CUSTOM,
    /** Administrative web GUI module. */
    ADMINWEB;

    @Override
    public boolean equals(ModuleType value) {
        if (value == null) {
            return false;
        }
        return this.toString().equals(value.toString());
    }
}
