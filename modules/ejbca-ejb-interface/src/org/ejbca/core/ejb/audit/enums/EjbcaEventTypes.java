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
package org.ejbca.core.ejb.audit.enums;

import org.cesecore.audit.enums.EventType;

/**
 * EJBCA specific event types, for audit using CESecore's audit log.
 * 
 * @version $Id$
 * 
 */
public enum EjbcaEventTypes implements EventType {
    PUBLISHER_CHANGE,
    PUBLISHER_CLONE,
    PUBLISHER_CREATION,
    PUBLISHER_REMOVAL,
    PUBLISHER_RENAME,
    PUBLISHER_STORE_CERTIFICATE,
    PUBLISHER_STORE_CRL,
    PUBLISHER_TEST_CONNECTION,
    CA_SIGNREQUEST,
    CA_RENEWED,
    CA_REVOKED,
    CA_IMPORT,
    CA_EXPORTTOKEN,
    CA_REMOVETOKEN,
    CA_RESTORETOKEN,
    CA_VALIDITY,
    CA_USERAUTH,
    RA_ADDENDENTITY,
    RA_EDITENDENTITY,
    RA_DELETEENDENTITY,
    RA_REVOKEDENDENTITY,
    RA_ADDEEPROFILE,
    RA_EDITEEPROFILE,
    RA_REMOVEEEPROFILE,
    RA_RENAMEEEPROFILE,
    RA_ADDADMINPREF,
    RA_DEFAULTADMINPREF,
    RA_EDITADMINPREF,
    RA_USERDATASOURCEFETCHDATA,
    RA_USERDATASOURCEREMOVEDATA,
    RA_USERDATASOURCEADD,
    RA_USERDATASOURCEEDIT,
    RA_USERDATASOURCEREMOVE,
    RA_USERDATASOURCERENAME,
    REVOKE_UNREVOKEPUBLISH,
    CUSTOMLOG_ERROR,
    CUSTOMLOG_INFO,
    HARDTOKEN_GENERATE,
    HARDTOKEN_ADD,
    HARDTOKEN_EDIT,
    HARDTOKEN_REMOVE,
    HARDTOKEN_VIEWED,
    HARDTOKEN_VIEWEDPUK,
    HARDTOKEN_ADDPROFILE,
    HARDTOKEN_EDITPROFILE,
    HARDTOKEN_REMOVEPROFILE,
    HARDTOKEN_ADDISSUER,
    HARDTOKEN_REMOVEISSUER,
    HARDTOKEN_EDITISSUER,
    HARDTOKEN_ADDCERTMAP,
    HARDTOKEN_REMOVECERTMAP,
    KEYRECOVERY_SENT,
    KEYRECOVERY_MARKED,
    KEYRECOVERY_ADDDATA,
    KEYRECOVERY_EDITDATA,
    KEYRECOVERY_REMOVEDATA,
    APPROVAL_ADD,
    APPROVAL_REMOVE,
    APPROVAL_APPROVE,
    APPROVAL_REJECT,
    SYSTEMCONF_EDIT,
    SYSTEMCONF_CREATE,
    SERVICE_ADD,
    SERVICE_REMOVE,
    SERVICE_EDIT,
    SERVICE_RENAME,
    SERVICE_EXECUTED,
    ADMINWEB_ADMINISTRATORLOGGEDIN
    ;

    @Override
    public boolean equals(EventType value) {
        if (value == null) {
            return false;
        }
        return this.toString().equals(value.toString());
    }

}
