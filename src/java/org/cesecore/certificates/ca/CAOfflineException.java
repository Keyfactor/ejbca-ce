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

import org.cesecore.CesecoreException;
import org.cesecore.ErrorCode;


/**
 * An exception thrown when someone tries to use a CA that is off line
 *
 * @author  Tomas Gustavsson
 * Based on EJBCA version: CAOfflineException.java 8373 2009-11-30 14:07:00Z jeklund
 * 
 * @version $Id: CAOfflineException.java 158 2011-01-26 14:48:51Z mikek $
 */
public class CAOfflineException extends CesecoreException {

    private static final long serialVersionUID = 6138811845234513758L;


    /**
     * Creates a new instance of <code>CAOfflineException</code> without detail message.
     */
    public CAOfflineException() {
        super();
        super.setErrorCode(ErrorCode.CA_OFFLINE);
    }
    
    
    /**
     * Constructs an instance of <code>CAOfflineException</code> with the specified detail message.
     * @param msg the detail message.
     */
    public CAOfflineException(String msg) {
        super(ErrorCode.CA_OFFLINE, msg);
    }
}
