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
 * AdmingroupExistsException.java
 *
 * Created on den 23 mars 2002, 19:44
 */

package org.ejbca.core.model.authorization;

/**
 * An exception thrown when someone tries to add a admingroup that already exits
 *
 * @author  Philip Vendil
 * @version $Id$
 */
public class AdminGroupExistsException extends java.lang.Exception {

    /**
     * Creates a new instance of <code>AdmingroupExistsException</code> without detail message.
     */
    public AdminGroupExistsException() {
        super();
    }


    /**
     * Constructs an instance of <code>AdmingroupExistsException</code> with the specified detail message.
     * @param msg the detail message.
     */
    public AdminGroupExistsException(String msg) {
        super(msg);
    }
}
