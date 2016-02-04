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
package org.cesecore.certificates.ca;

import javax.ejb.ApplicationException;

import org.cesecore.CesecoreException;
import org.cesecore.ErrorCode;


/**
 * An exception thrown when CA Name Change renewal could not be completed.
 *
 * @version $Id: CADoesntExistsException.java 17625 2013-09-20 07:12:06Z netmackan $
 */
@ApplicationException(rollback=true)
public class CANameChangeRenewalException extends CesecoreException {
    
    private static final long serialVersionUID = 1542504214401684378L;

    /**
     * Creates a new instance of <code>CANameChangeRenewalException</code> without detail message.
     */
    public CANameChangeRenewalException() {
        super(ErrorCode.CA_NAME_CHANGE_RENEWAL_ERROR);
    }
        
    /**
     * Constructs an instance of <code>CANameChangeRenewalException</code> with the specified detail message.
     * @param msg the detail message.
     */
    public CANameChangeRenewalException(String msg) {
        super(ErrorCode.CA_NAME_CHANGE_RENEWAL_ERROR, msg);
    }

    /**
     * Constructs an instance of <code>CANameChangeRenewalException</code> with the specified cause.
     * @param msg the detail message.
     */
    public CANameChangeRenewalException(Exception e) {
        super(e);
    }
}