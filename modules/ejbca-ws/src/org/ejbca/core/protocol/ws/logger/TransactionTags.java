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
package org.ejbca.core.protocol.ws.logger;

public enum TransactionTags {
    METHOD,
    ERROR_MESSAGE,
    ADMIN_DN,
    ADMIN_ISSUER_DN,
    ADMIN_REMOTE_IP,
    ADMIN_FORWARDED_IP;
    public String getTag() {
        return "${"+toString()+"}";
    }
}
