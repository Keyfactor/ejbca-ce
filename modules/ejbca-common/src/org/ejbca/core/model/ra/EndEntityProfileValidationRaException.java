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
import org.ejbca.core.model.ra.raadmin.EndEntityProfileValidationException;
import org.cesecore.ErrorCode;
import org.cesecore.NonSensitiveException;

/**
 * Wraps the original UserDoesntFullfillEndEntityProfile. Unlike original it doesn't
 * extend Exception and it's not marked with @WebFault.
 *
 * @version $Id$
 * @see UserDoesntFullfillEndEntityProfile
 */
@NonSensitiveException
public class EndEntityProfileValidationRaException extends EjbcaException {
    private static final long serialVersionUID = 777317800935352658L;

    public EndEntityProfileValidationRaException(EndEntityProfileValidationException exception){
        super(exception);
        setErrorCode(ErrorCode.USER_DOESNT_FULFILL_END_ENTITY_PROFILE);
    }
}
