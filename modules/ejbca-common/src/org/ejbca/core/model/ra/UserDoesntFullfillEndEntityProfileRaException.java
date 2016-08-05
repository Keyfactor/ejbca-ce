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
 
package org.ejbca.core.model.ra;

import org.ejbca.core.EjbcaException;
import org.ejbca.core.model.ra.raadmin.UserDoesntFullfillEndEntityProfile;
import org.cesecore.ErrorCode;
import org.cesecore.NonSensitiveException;

/**
 * Wraps the original UserDoesntFullfillEndEntityProfile. Unlike original it doesn't
 * extends Exception and it's not marked with @WebFault.
 *
 * @version $Id$
 */
@NonSensitiveException
public class UserDoesntFullfillEndEntityProfileRaException extends EjbcaException {
    private static final long serialVersionUID = 777317800935352658L;

    public UserDoesntFullfillEndEntityProfileRaException(UserDoesntFullfillEndEntityProfile exception){
        super(exception);
        setErrorCode(ErrorCode.USER_DOESNT_FULLFILL_END_ENTITY_PROFILE);
    }
}
