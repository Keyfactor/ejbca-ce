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
package org.cesecore.certificates.ocsp.exception;

/**
 * Thrown when a byte array couldn't be formed into a proper OCSP request.
 * 
 * @version $Id: MalformedRequestException.java 488 2011-03-09 15:49:46Z mikek $
 * 
 */
public class MalformedRequestException extends Exception {

    private static final long serialVersionUID = -6603931681530067622L;

    public MalformedRequestException() {

    }

    /**
     * @param arg0
     */
    public MalformedRequestException(String arg0) {
        super(arg0);
    }

    /**
     * @param arg0
     */
    public MalformedRequestException(Throwable arg0) {
        super(arg0);
    }

    /**
     * @param arg0
     * @param arg1
     */
    public MalformedRequestException(String arg0, Throwable arg1) {
        super(arg0, arg1);
    }

}
