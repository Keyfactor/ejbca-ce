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

/** Error processing the extended CA Service request
 * 
 * Based on EJBCA version: ExtendedCAServiceRequestException.java 8373 2009-11-30 14:07:00Z jeklund $
 * 
 * @version $Id$
 */
public class ExtendedCAServiceRequestException extends java.lang.Exception {
    
    private static final long serialVersionUID = -7017580940361778607L;

    /**
     * Creates a new instance of <code>ExtendedCAServiceRequestException</code> without detail message.
     */
    public ExtendedCAServiceRequestException() {
        super();
    }
        
    /**
     * Constructs an instance of <code>ExtendedCAServiceRequestException</code> with the specified detail message.
     * @param msg the detail message.
     */
    public ExtendedCAServiceRequestException(String msg) {
        super(msg);
    }

    /**
     * Constructs an instance of <code>ExtendedCAServiceRequestException</code> with the specified cause.
     * @param msg the detail message.
     */
    public ExtendedCAServiceRequestException(Exception e) {
        super(e);
    }
}
