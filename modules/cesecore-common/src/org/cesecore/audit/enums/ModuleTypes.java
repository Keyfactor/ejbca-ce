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
 * When doing secure audit log it is necessary to identify from which module a security audit event originates.
 *
 * A modules is a group of related functionality. This class contains the modules in the CESeCore core itself.
 * 
 * @see org.cesecore.audit.enums.EventTypes
 * @see org.cesecore.audit.enums.ServiceTypes
 * @version $Id$
 */
public enum ModuleTypes implements ModuleType {
	/** Access control module. */
	ACCESSCONTROL,
	/** Authentication module. */
	AUTHENTICATION,
	/** Certificate Authority module. */
	CA,
	/** Certificate issuance and handling module. */
	CERTIFICATE,
	/** Certificate profile module. */
	CERTIFICATEPROFILE,
    /** Certificate Revocation List issuance and handling module. */
	CRL,
    /** Crypto Token module. */
    CRYPTOTOKEN,
    /** <i>Module type is currently not used in EJBCA.</i> */
	KEY_MANAGEMENT,
	/** <i>Module type for blacklist.</i> */
    BLACKLIST,
	/** <i>Module type for Key validator.</i> */
    VALIDATOR,
    /** <i>Module type is currently not used in EJBCA.</i> */
	RECOVERY,
	/** Administrator role management module. */
	ROLES,
    /** Security event audit log module. */
	SECURITY_AUDIT,
    /** <i>Module type is currently not used in EJBCA.</i> */
	TRUSTED_TIME,
    /** Internal Key Binding module. */
	INTERNALKEYBINDING,
    /** Module for system settings stored in the database. */
    GLOBALCONF;

    @Override
    public boolean equals(ModuleType value) {
        if(value == null) {
            return false;
        }
        return this.toString().equals(value.toString());
    }

}
