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
package org.cesecore.dbprotection;



/**
 * An exception thrown when there is an error with database protection, this error is fatal and should lead to 
 * application not working, thus the use of RuntimeException.
 *
 * Based on CESeCore version:
 *      DatabaseProtectionError.java 897 2011-06-20 11:17:25Z johane
 *  
 * @version $Id$
 */
public class DatabaseProtectionError extends RuntimeException {
    
    private static final long serialVersionUID = -1L;

    /* We don't want to send raw database entries outside the JVM. */
    private transient final ProtectedData entity;

    /**
     * Constructs an instance of exception with a simple details message
     * and the read entity causing the error.
     */
    public DatabaseProtectionError(final String msg, final ProtectedData entity) {
        super(msg);
        this.entity = entity;
    }

    /**
     * Constructs an instance of exception with a simple details message
     */
    public DatabaseProtectionError(final String msg) {
        super(msg);
        this.entity = null;
    }

    /**
     * Constructs an instance of exception wrapping the causing error
     */
    public DatabaseProtectionError(final Exception e) {
        super(e);
        this.entity = null;
    }
    
    /** @return the entity that we tried to read that failed the verification. */
    public ProtectedData getEntity() {
    	return entity;
    }
}
