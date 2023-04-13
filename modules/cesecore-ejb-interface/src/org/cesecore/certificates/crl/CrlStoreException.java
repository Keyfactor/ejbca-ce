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
package org.cesecore.certificates.crl;

import javax.ejb.ApplicationException;

import com.keyfactor.CesecoreException;


/**
 * An exception thrown when an error happens trying to add CRLs to the CRL store. 
 * If this happens any transaction depending on this should be rolled back.
 * 
 *
 * @version $Id$
 */
@ApplicationException(rollback=true)  
public class CrlStoreException extends CesecoreException {
    
    private static final long serialVersionUID = -642610825885468919L;


    /**
     * Creates a new instance of exception without detail message.
     * Marked as rollback=true
     * @see CrlStoreException
     */
    public CrlStoreException() {
        super();
    }
    
    
    /**
     * Constructs an instance of exception with the specified detail message.
     * Marked as rollback=true
     * @see CrlStoreException
     * @param msg the detail message.
     */
    public CrlStoreException(String msg) {
        super(msg);
    }

    /** 
     * Marked as rollback=true
     * @see CrlStoreException
     * @param e causing exception that will be wrapped
     */
    public CrlStoreException(Exception e) {
        super(e);
    }

}
