/*************************************************************************
 *                                                                       *
 *  EJBCA: The OpenSource Certificate Authority                          *
 *                                                                       *
 *  This software is free software; you can redistribute it and/or       *
 *  modify it under the terms of the GNU Lesser General Public           *
 *  License as published by the Free Software Foundation; either         *
 *  version 2.1 of the License, or any later version.                    *
 *                                                                       *
 *  See terms of license at gnu.org.                                     *
 *                                                                       *
 *************************************************************************/
package org.cesecore.accounts;

/**
 * Custom exception for account binding identifier verification.
 */
public class AccountBindingException extends Exception {

    private static final long serialVersionUID = 575491716550831917L;

    /**
     * Default constructor.
     * 
     * @param message the human readable message.
     * @param cause the nested exception.
     */
    public AccountBindingException(String message, Throwable cause) {
        super(message, cause);
    }

    /**
     * Default constructor.
     * 
     * @param message the human readable message.
     */
    public AccountBindingException(String message) {
        super(message);
    }

}
