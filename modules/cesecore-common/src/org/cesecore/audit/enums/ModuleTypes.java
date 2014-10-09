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
package org.cesecore.audit.enums;

/**
 * Represents the basic module types supported.
 *
 * When doing secure audit log it is necessary to identify wich CESeCore module is loggin.
 * 
 * @version $Id$
 * 
 */
public enum ModuleTypes implements ModuleType {
	
	ACCESSCONTROL,
	AUTHENTICATION,
	CA,
	CERTIFICATE,
	CERTIFICATEPROFILE,
	CRL,
    CRYPTOTOKEN,
	KEY_MANAGEMENT,
	RECOVERY,
	ROLES,
	SECURITY_AUDIT,
	TRUSTED_TIME,
	INTERNALKEYBINDING,
    GLOBALCONF;

    @Override
    public boolean equals(ModuleType value) {
        if(value == null) {
            return false;
        }
        return this.toString().equals(value.toString());
    }

}
