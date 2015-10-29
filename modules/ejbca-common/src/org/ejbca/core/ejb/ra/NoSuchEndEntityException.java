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
package org.ejbca.core.ejb.ra;

import org.cesecore.CesecoreException;

/**
 * An exception thrown when an end entity is thought to exist but does not.
 *
 * @version $Id$
 */
public class NoSuchEndEntityException extends CesecoreException {

    private static final long serialVersionUID = -6700250563735120223L;

    public NoSuchEndEntityException() {
        super();
    }
    
    public NoSuchEndEntityException(String msg) {
        super(msg);
    }
    
    public NoSuchEndEntityException(String msg, Throwable e) {
        super(msg, e);
    }
}
