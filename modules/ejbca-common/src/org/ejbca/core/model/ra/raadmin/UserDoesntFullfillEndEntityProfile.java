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
 
package org.ejbca.core.model.ra.raadmin;

import javax.xml.ws.WebFault;

/**
 * An exception thrown when someone tries to add or edit a profile that doesn't match its end entity
 * profile.
 *
 * @version $Id$
 * 
 * @deprecated since EJBCA 6.7.0 but kept for legacy support of WS interface, where we can't modify methods. For all other cases, 
 *             EndEntityProfileValidationException should be used instead. 
 */
@WebFault
@Deprecated
public class UserDoesntFullfillEndEntityProfile extends Exception {
    private static final long serialVersionUID = 777317800935352658L;

    /**
     * Creates a new instance of <code>UserDoesntFullfillProfile</code> without detail message.
     */
    public UserDoesntFullfillEndEntityProfile() {
        super();
    }

    /**
     * Constructs an instance of <code>UserDoesntFullfillProfile</code> with the specified detail
     * message.
     *
     * @param msg the detail message.
     */
    public UserDoesntFullfillEndEntityProfile(String msg) {
        super(msg);
    }
    
    public UserDoesntFullfillEndEntityProfile(Throwable e) {
        super(e);
    }
}
