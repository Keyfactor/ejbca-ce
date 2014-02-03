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
 * General RuntimeException for OCSP error that can't be handled.
 * 
 * @version $Id$
 *
 */
public class OcspFailureException extends RuntimeException {

    private static final long serialVersionUID = 3024801898030204798L;

    /**
     * 
     */
    public OcspFailureException() {
    
    }

    /**
     * @param arg0
     */
    public OcspFailureException(String msg) {
        super(msg);

    }

    /**
     * @param arg0
     */
    public OcspFailureException(Throwable t) {
        super(t);

    }

    /**
     * @param arg0
     * @param arg1
     */
    public OcspFailureException(String msg, Throwable t) {
        super(msg, t);
        
    }

}
