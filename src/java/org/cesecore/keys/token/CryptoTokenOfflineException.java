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
package org.cesecore.keys.token;

import org.cesecore.CesecoreException;
import org.cesecore.ErrorCode;


/**
 * An exception thrown when someone tries to use a CA Token that isn't available
 *
 * Based on EJBCA version: 
 *      CATokenOfflineException.java 8373 2009-11-30 14:07:00Z jeklund
 * CESeCore version:
 *      CryptoTokenOfflineException.java 922 2011-07-04 09:01:47Z mikek
 * 
 * @version $Id$
 */
public class CryptoTokenOfflineException extends CesecoreException {
    
    private static final long serialVersionUID = -4228966531990184850L;


    /**
     * Creates a new instance of <code>CATokenOfflineException</code> without detail message.
     */
    public CryptoTokenOfflineException() {
        super();
        super.setErrorCode(ErrorCode.CA_OFFLINE);
    }
    
    
    /**
     * Constructs an instance of <code>CATokenOfflineException</code> with the specified detail message.
     * @param msg the detail message.
     */
    public CryptoTokenOfflineException(String msg) {
        super(ErrorCode.CA_OFFLINE, msg);
    }

    public CryptoTokenOfflineException(Exception e) {
        super(ErrorCode.CA_OFFLINE, e);
    }
    public CryptoTokenOfflineException(String msg, Exception e) {
        super(ErrorCode.CA_OFFLINE, msg, e);
    }

}
