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

package org.ejbca.core.model.keyimport;

import org.ejbca.core.EjbcaException;
import jakarta.ejb.ApplicationException;

@ApplicationException(rollback=true)
public class KeyImportException extends EjbcaException {

    public KeyImportException(String message) {
        super(message);
    }
}
