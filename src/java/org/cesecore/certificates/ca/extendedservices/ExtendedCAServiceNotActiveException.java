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

/**
 * Based on EJBCA version: ExtendedCAServiceNotActiveException.java 8373 2009-11-30 14:07:00Z jeklund $
 * 
 * @version $Id: ExtendedCAServiceNotActiveException.java 158 2011-01-26 14:48:51Z mikek $
 */
public class ExtendedCAServiceNotActiveException extends java.lang.Exception {
    
    private static final long serialVersionUID = -4585542922703140980L;

    /**
     * Creates a new instance of <code>ExtendedCAServiceNotActiveException</code> without detail message.
     */
    public ExtendedCAServiceNotActiveException() {
        super();
    }
        
    /**
     * Constructs an instance of <code>ExtendedCAServiceNotActiveException</code> with the specified detail message.
     * @param msg the detail message.
     */
    public ExtendedCAServiceNotActiveException(String msg) {
        super(msg);
    }

    /**
     * Constructs an instance of <code>IllegalExtendedServiceRequestException</code> with the specified cause.
     * @param msg the detail message.
     */
    public ExtendedCAServiceNotActiveException(Exception e) {
        super(e);
    }
}
