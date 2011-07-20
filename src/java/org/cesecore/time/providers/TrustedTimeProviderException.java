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
package org.cesecore.time.providers;   

/**
 * This exception should be used on TrustedTime provider errors.
 *
 * Based on CESeCore version:
 *      TrustedTimeProviderException.java 800 2011-05-17 11:23:26Z filiper
 *
 * @version $Id$
 * 
 */ 
public class TrustedTimeProviderException extends Exception {

    private static final long serialVersionUID = -7860047748193141529L;

    /**
     * @see Exception#Exception()
     */
    public TrustedTimeProviderException()
    {
        super();
    }

    /**
     * @see Exception#Exception(String)
     */
    public TrustedTimeProviderException(String message)
    {
        super(message);
    }

    /**
     * @see Exception#Exception(String,Throwable)
     */
    public TrustedTimeProviderException(String message, Throwable cause)
    {
        super(message, cause);
    }

    /**
     * @see Exception#Exception(Throwable)
     */
    public TrustedTimeProviderException(Throwable cause)
    {
        super(cause);
    }
}
