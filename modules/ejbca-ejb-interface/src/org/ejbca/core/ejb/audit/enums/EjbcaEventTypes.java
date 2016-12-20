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
 * EJBCA specific security audit event types, for audit using CESecore's audit log.
 * 
 * These event types extend the list of already existing event types of CESeCore.
 * 
 * @see org.cesecore.audit.enums.EventTypes
 * @see org.ejbca.core.ejb.audit.enums.EjbcaModuleTypes
 * @see org.ejbca.core.ejb.audit.enums.EjbcaServiceTypes
 * @version $Id$
 */
public enum EjbcaEventTypes implements EventType {
    /** An administrator logs in to EJBCA's Administrative Web GUI. */
    ADMINWEB_ADMINISTRATORLOGGEDIN,
    /** Action that requires approval by one or more administrators is requested. */
    APPROVAL_ADD,
    /** Action that requires approval was approved by one of the required administrator(s). */
    APPROVAL_APPROVE,
    /** Approval request was edited. */
    APPROVAL_EDIT,
    /** Action that requires approval was rejected by one of the required administrator(s). */
    APPROVAL_REJECT,
    /** <i>Event type is currently only used by EJBCA development tests.</i> */
    APPROVAL_REMOVE,
    /** Expiration date of an approval request was extended by an administrator. */
    APPROVAL_UNEXPIRE,
    /** Adding an approval profile */
    APPROVAL_PROFILE_ADD,
    /** Editing an approval profile */
    APPROVAL_PROFILE_EDIT,
    /** Removing an approval profile */
    APPROVAL_PROFILE_REMOVE,
    /** Renaming an approval profile */
    APPROVAL_PROFILE_RENAME,
    /** Export of a Certificate Authority's (soft) Crypto Token. */
    CA_EXPORTTOKEN,
    /** Execution of one of the Certificate Authority's extended services. */
    CA_EXTENDEDSERVICE,
    /** Creation of a Certificate Authority using an existing soft key store. */
    CA_IMPORT,
    /** Removal of a Certificate Authority's (soft) Crypto Token. */
    CA_REMOVETOKEN,
    /** Renewal of a Certificate Authority's certificate, optionally using a different key pair. */
    CA_RENEWED,
    /** Roll over of a Certificates Authority's certificate chain and key. */
    CA_ROLLEDOVER,
    /** Restoration of a Certificate Authority's previously removed (soft) Crypto Token. */
    CA_RESTORETOKEN,
    /** Revocation of a Certificate Authority and all certificates issued by it. */
    CA_REVOKED,
    /** Certificate Authority signs (attests) a provided certificate signing request. */
    CA_SIGNREQUEST,
    /** Certificate Authority signs (attests) a CMS / PKCS#7. */
    CA_SIGNCMS,
    /** End entity authenticates using enrollment code. */
    CA_USERAUTH,
    /** Certificate Authority's signing certificate is not valid yet or not valid any longer. */
    CA_VALIDITY,
    /** Log entry with log level error supplied from external source. */
    CUSTOMLOG_ERROR,
    /** Log entry with log level info supplied from external source. */
    CUSTOMLOG_INFO,
    /** Application startup. */
    EJBCA_STARTING,
    /** Creation of a new (client) hardware token representation. */
    HARDTOKEN_ADD,
    /** Creation of link from a (client) hardware token representation to a certificate. */
    HARDTOKEN_ADDCERTMAP,
    /** Creation of a new issuer for (client) hardware tokens. */
    HARDTOKEN_ADDISSUER,
    /** Creation of a new template for (client) hardware tokens. */
    HARDTOKEN_ADDPROFILE,
    /** Modification of an existing (client) hardware token representation. */
    HARDTOKEN_EDIT,
    /** Modification or name change of an existing issuer for (client) hardware tokens. */
    HARDTOKEN_EDITISSUER,
    /** Modification or name change of an existing template for (client) hardware tokens. */
    HARDTOKEN_EDITPROFILE,
    /** Outcome of provisioning of a (client) hardware token reported by external card management system. */
    HARDTOKEN_GENERATE,
    /** Removal of an existing (client) hardware token representation. */
    HARDTOKEN_REMOVE,
    /** Removal of link from a (client) hardware token representation to a certificate. */
    HARDTOKEN_REMOVECERTMAP,
    /** Removal of an existing issuer for (client) hardware tokens. */
    HARDTOKEN_REMOVEISSUER,
    /** Removal of an existing template for (client) hardware tokens. */
    HARDTOKEN_REMOVEPROFILE,
    /** Administrator views the content of a (client) hardware token representation. */
    HARDTOKEN_VIEWED,
    /** Administrator views the PUK code of a (client) hardware token representation. */
    HARDTOKEN_VIEWEDPUK,
    /** Persistence of encrypted key material and meta data that can be used for recovering a server-side generated client key pair. */
    KEYRECOVERY_ADDDATA,
    /** Modification of encrypted key material and meta data that can be used for recovering a server-side generated client key pair. */
    KEYRECOVERY_EDITDATA,
    /** Change status of meta data for encrypted key material to allow extraction of server-side generated client key pair. */
    KEYRECOVERY_MARKED,
    /** Removal of specific or all encrypted key material and meta data that can be used for recovering a server-side generated client key pair. */
    KEYRECOVERY_REMOVEDATA,
    /** Extraction of key material of server-side generated client key pair. */
    KEYRECOVERY_SENT,
    /** Modification of an existing publisher. */
    PUBLISHER_CHANGE,
    /** Creation of a new publisher. */
    PUBLISHER_CREATION,
    /** Removal of an existing publisher. */
    PUBLISHER_REMOVAL,
    /** Name change of an existing publisher. */
    PUBLISHER_RENAME,
    /** Publishing of a certificate and/or related certificate meta data. */
    PUBLISHER_STORE_CERTIFICATE,
    /** Publishing of a Certificate Revocation List and related meta data. */
    PUBLISHER_STORE_CRL,
    /** Creation of new settings for an administrator. */
    RA_ADDADMINPREF,
    /** Creation of a new end entity profile. */
    RA_ADDEEPROFILE,
    /** Creation of a new end entity. */
    RA_ADDENDENTITY,
    /** Modification of default settings for administrators. */
    RA_DEFAULTADMINPREF,
    /** Removal of a new end entity profile. */
    RA_DELETEENDENTITY,
    /** Modification of an existing settings for an administrator. */
    RA_EDITADMINPREF,
    /** Modification of an existing end entity profile. */
    RA_EDITEEPROFILE,
    /** Modification of an existing end entity. */
    RA_EDITENDENTITY,
    /** Removal of an existing end entity profile. */
    RA_REMOVEEEPROFILE,
    /** Name change of an existing end entity profile. */
    RA_RENAMEEEPROFILE,
    /** Change status of an existing end entity and all the end entity's certificates to revoked. */
    RA_REVOKEDENDENTITY,
    /** Creation of a new user data source. */
    RA_USERDATASOURCEADD,
    /** Modification of an existing user data source. */
    RA_USERDATASOURCEEDIT,
    /** Retrieval of data through an existing user data source. */
    RA_USERDATASOURCEFETCHDATA,
    /** Removal of an existing user data source. */
    RA_USERDATASOURCEREMOVE,
    /** Request for removal of data through an existing user data source. */
    RA_USERDATASOURCEREMOVEDATA,
    /** Name change of an existing user data source. */
    RA_USERDATASOURCERENAME,
    /** Publishing of a certificate and/or related certificate meta data when certificate is activated after being on hold. */
    REVOKE_UNREVOKEPUBLISH,
    /** Creation of a new EJBCA background service. */
    SERVICE_ADD,
    /** Modification of an existing EJBCA background service. */
    SERVICE_EDIT,
    /** <i>Event type is currently not used in EJBCA.</i> */
    SERVICE_EXECUTED,
    /** Removal of an existing EJBCA background service. */
    SERVICE_REMOVE,
    /** Name change of an existing EJBCA background service. */
    SERVICE_RENAME
    ;

    @Override
    public boolean equals(EventType value) {
        if (value == null) {
            return false;
        }
        return this.toString().equals(value.toString());
    }

}
