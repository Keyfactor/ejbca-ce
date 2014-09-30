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
package org.ejbca.core.ejb.audit.enums;

import org.cesecore.audit.enums.EventType;

/**
 * EJBCA specific event types, for audit using CESecore's audit log.
 * 
 * @version $Id$
 * 
 */
public enum EjbcaEventTypes implements EventType {
    ADMINWEB_ADMINISTRATORLOGGEDIN,
    APPROVAL_ADD,
    APPROVAL_APPROVE,
    APPROVAL_REJECT,
    APPROVAL_REMOVE,
    CA_EXPORTTOKEN,
    CA_EXTENDEDSERVICE,
    CA_IMPORT,
    CA_REMOVETOKEN,
    CA_RENEWED,
    CA_RESTORETOKEN,
    CA_REVOKED,
    CA_SIGNREQUEST,
    CA_USERAUTH,
    CA_VALIDITY,
    CUSTOMLOG_ERROR,
    CUSTOMLOG_INFO,
    EJBCA_STARTING,
    HARDTOKEN_ADD,
    HARDTOKEN_ADDCERTMAP,
    HARDTOKEN_ADDISSUER,
    HARDTOKEN_ADDPROFILE,
    HARDTOKEN_EDIT,
    HARDTOKEN_EDITISSUER,
    HARDTOKEN_EDITPROFILE,
    HARDTOKEN_GENERATE,
    HARDTOKEN_REMOVE,
    HARDTOKEN_REMOVECERTMAP,
    HARDTOKEN_REMOVEISSUER,
    HARDTOKEN_REMOVEPROFILE,
    HARDTOKEN_VIEWED,
    HARDTOKEN_VIEWEDPUK,
    KEYRECOVERY_ADDDATA,
    KEYRECOVERY_EDITDATA,
    KEYRECOVERY_MARKED,
    KEYRECOVERY_REMOVEDATA,
    KEYRECOVERY_SENT,
    PUBLISHER_CHANGE,
    PUBLISHER_CREATION,
    PUBLISHER_REMOVAL,
    PUBLISHER_RENAME,
    PUBLISHER_STORE_CERTIFICATE,
    PUBLISHER_STORE_CRL,
    RA_ADDADMINPREF,
    RA_ADDEEPROFILE,
    RA_ADDENDENTITY,
    RA_DEFAULTADMINPREF,
    RA_DELETEENDENTITY,
    RA_EDITADMINPREF,
    RA_EDITEEPROFILE,
    RA_EDITENDENTITY,
    RA_REMOVEEEPROFILE,
    RA_RENAMEEEPROFILE,
    RA_REVOKEDENDENTITY,
    RA_USERDATASOURCEADD,
    RA_USERDATASOURCEEDIT,
    RA_USERDATASOURCEFETCHDATA,
    RA_USERDATASOURCEREMOVE,
    RA_USERDATASOURCEREMOVEDATA,
    RA_USERDATASOURCERENAME,
    REVOKE_UNREVOKEPUBLISH,
    SERVICE_ADD,
    SERVICE_EDIT,
    SERVICE_EXECUTED,
    SERVICE_REMOVE,
    SERVICE_RENAME,
    SYSTEMCONF_CREATE,
    SYSTEMCONF_EDIT
    ;

    @Override
    public boolean equals(EventType value) {
        if (value == null) {
            return false;
        }
        return this.toString().equals(value.toString());
    }

}
