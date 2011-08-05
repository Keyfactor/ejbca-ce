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
package org.cesecore.certificates.ca.extendedservices;

/** Used for illegal (invalid) CA Service Requests
 * 
 * Based on EJBCA version: IllegalExtendedCAServiceRequestException.java 8373 2009-11-30 14:07:00Z jeklund $
 * 
 * @version $Id: IllegalExtendedCAServiceRequestException.java 158 2011-01-26 14:48:51Z mikek $
 */
public class IllegalExtendedCAServiceRequestException extends Exception {
    
    private static final long serialVersionUID = 2715976842113419606L;

    /**
     * Creates a new instance of <code>IllegalExtendedCAServiceRequestException</code> without detail message.
     */
    public IllegalExtendedCAServiceRequestException() {
        super();
    }
        
    /**
     * Constructs an instance of <code>IllegalExtendedCAServiceRequestException</code> with the specified detail message.
     * @param msg the detail message.
     */
    public IllegalExtendedCAServiceRequestException(String msg) {
        super(msg);
    }

    /**
     * Constructs an instance of <code>IllegalExtendedCAServiceRequestException</code> with the specified cause.
     * @param msg the detail message.
     */
    public IllegalExtendedCAServiceRequestException(Exception e) {
        super(e);
    }
}
