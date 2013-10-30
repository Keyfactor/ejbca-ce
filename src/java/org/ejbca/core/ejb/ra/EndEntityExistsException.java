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
package org.ejbca.core.ejb.ra;

import org.cesecore.CesecoreException;

/**
 * An exception thrown when someone tries to create and end-entity that already exists.
 *
 * @version $Id$
 */
public class EndEntityExistsException extends CesecoreException {

    private static final long serialVersionUID = -6700250563735120223L;

    public EndEntityExistsException() {
        super();
    }
    
    public EndEntityExistsException(String msg) {
        super(msg);
    }
}
