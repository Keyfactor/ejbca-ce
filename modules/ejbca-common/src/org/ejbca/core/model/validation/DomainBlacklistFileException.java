/*************************************************************************
 *                                                                       *
 *  CESeCore: CE Security Core 
                                          *
 *                                                                       *
 *  This software is free software; you can redistribute it and/or       *
 *  modify it under the terms of the GNU Lesser General Public           *
 *  License as published by the Free Software Foundation; either         *
 *  version 2.1 of the License, or any later version.                    *
 *                                                                       *
 *  See terms of license at gnu.org.                                     *
 *                                                                       *
 *************************************************************************/
package org.ejbca.core.model.validation;

import org.cesecore.CesecoreException;
import org.cesecore.ErrorCode;

/**
 * An exception thrown when trying to parse a malformed blacklist file.
 * @version $Id:$
 */
public class DomainBlacklistFileException extends CesecoreException {
    private static final long serialVersionUID = 1L;
    
    /**
     * Creates a new instance without detail message.
     */
    public DomainBlacklistFileException() {
        super(ErrorCode.DOMAIN_BLACKLIST_FILE_PARSING_FAILED);
    }
        
    /**
     * Constructs an instance of with the specified detail message.
     * @param msg the detail message.
     */
    public DomainBlacklistFileException(String msg) {
        super(ErrorCode.DOMAIN_BLACKLIST_FILE_PARSING_FAILED, msg);
    }

    /**
     * Constructs an instance of with the specified cause.
     * @param e the specified cause.
     */
    public DomainBlacklistFileException(Exception e) {
        super(ErrorCode.DOMAIN_BLACKLIST_FILE_PARSING_FAILED, e);
    }


}
