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
package org.ejbca.core.model.approval;

import java.io.Serializable;
import java.util.Date;

import org.cesecore.authentication.tokens.AuthenticationToken;

/**
 * Holds an authentication token (admin) and a timestamp.
 * @version $Id$
 */
public final class TimeAndAdmin implements Serializable {

    private static final long serialVersionUID = 1L;
    
    private final Date date;
    private final AuthenticationToken admin;

    public TimeAndAdmin(Date date, AuthenticationToken admin) {
        this.date = date;
        this.admin = admin;
    }

    public Date getDate() {
        return date;
    }

    public AuthenticationToken getAdmin() {
        return admin;
    }

}
