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
 * EJBCA specific security audit event module types, for audit using CESecore's audit log.
 * 
 * A modules is a group of related functionality.
 * These module types are part of EJBCA (not the core itself) and extend the list of already existing module types of CESeCore.
 * 
 * @see org.cesecore.audit.enums.ModuleTypes
 * @see org.ejbca.core.ejb.audit.enums.EjbcaEventTypes
 * @see org.ejbca.core.ejb.audit.enums.EjbcaServiceTypes
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
    /** Approval Profiles module. */
    APPROVAL_PROFILE,
    /** Publisher module. */
    PUBLISHER,
    /** EJBCA background service module. */
    SERVICE,
    /** External logging module. */
    CUSTOM,
    /** Administrative web GUI module. */
    ADMINWEB,
    /** Blacklist module. */
    BLACKLIST;    

    @Override
    public boolean equals(ModuleType value) {
        if (value == null) {
            return false;
        }
        return this.toString().equals(value.toString());
    }
}
