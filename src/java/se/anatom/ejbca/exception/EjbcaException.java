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
 
package se.anatom.ejbca.exception;

/**
 * Base for all specific application exceptions thrown by EJBCA. Can be used to catch any
 * non-crititcal application exceptions thay may be possible to handle: <code> try { . . . } catch
 * (EjbcaException e) { error("Error: blahblah", e); ... }</code>
 *
 * @version $Id: EjbcaException.java,v 1.9 2004-04-16 07:38:59 anatom Exp $
 */
public class EjbcaException extends Exception {
    /**
     * Constructor used to create exception without an errormessage. Calls the same constructor in
     * baseclass <code>Exception</code>.
     */
    public EjbcaException() {
        super();
    }
    /**
     * Constructor used to create exception with an errormessage. Calls the same constructor in
     * baseclass <code>Exception</code>.
     *
     * @param message Human redable error message, can not be NULL.
     */
    public EjbcaException(String message) {
        super(message);
    }

    /**
     * Constructor used to create exception with an embedded exception. Calls the same constructor
     * in baseclass <code>Exception</code>.
     *
     * @param exception exception to be embedded.
     */
    public EjbcaException(Exception exception) {
        super(exception);
    }
}
