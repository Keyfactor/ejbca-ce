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
 
/*
 * EndEntityProfileDoesntExistsException.java
 *
 * Created on 13 juni 2002, 11:27
 */
package se.anatom.ejbca.ra.raadmin;

/**
 * An exception thrown when someone tries to add an end entity profile that already exits
 *
 * @author Philip Vendil
 */
public class EndEntityProfileDoesntExistsException extends java.lang.Exception {
    /**
     * Creates a new instance of <code>EndEntityProfileDoesntExistsException</code> without detail
     * message.
     */
    public EndEntityProfileDoesntExistsException() {
        super();
    }

    /**
     * Constructs an instance of <code>EndEntityProfileDoesntExistsException</code> with the
     * specified detail message.
     *
     * @param msg the detail message.
     */
    public EndEntityProfileDoesntExistsException(String msg) {
        super(msg);
    }
}
