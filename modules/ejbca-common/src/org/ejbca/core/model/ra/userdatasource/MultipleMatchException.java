/*************************************************************************
 *                                                                       *
 *  EJBCA Community: The OpenSource Certificate Authority                *
 *                                                                       *
 *  This software is free software; you can redistribute it and/or       *
 *  modify it under the terms of the GNU Lesser General Public           *
 *  License as published by the Free Software Foundation; either         *
 *  version 2.1 of the License, or any later version.                    *
 *                                                                       *
 *  See terms of license at gnu.org.                                     *
 *                                                                       *
 *************************************************************************/
 
package org.ejbca.core.model.ra.userdatasource;

import javax.xml.ws.WebFault;

import org.ejbca.core.EjbcaException;


/**
 * Is thrown during remove user data call and the search string matches multiple but 
 * the call is instructed not to remove more than one.
 *
 * @version $Id$
 */
@WebFault
public class MultipleMatchException extends EjbcaException {
    
    private static final long serialVersionUID = 5191918316722890271L;

    /**
     * Creates a new instance of <code>MultipleMatchException</code> without detail message.
     */
    public MultipleMatchException() {
        super();
    }
 
    /**
     * Constructs an instance of <code>MultipleMatchException</code> with the specified detail message.
     * @param msg the detail message.
     */
    public MultipleMatchException(String msg) {
        super(msg);
    }
}
