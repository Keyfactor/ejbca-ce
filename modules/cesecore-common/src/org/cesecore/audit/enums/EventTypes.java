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
package org.cesecore.audit.enums;

/**
 * Contains all event types that CESeCore core needs to log to secure audit log. 
 *
 * When doing secure audit log it is necessary to identify the event being logged.
 *
 * @version $Id$
 */
public enum EventTypes implements EventType {

    /** Authorization check to resource of authenticated entity. */
    ACCESS_CONTROL,
    /** Authentication check of an entity. */
    AUTHENTICATION,
    /** Creation of a Certificate Authority. */
    CA_CREATION,
    /** Removal of a Certificate Authority. */
    CA_DELETION,
    /** Internal application name change of a Certificate Authority. Unrelated to Certificate Authority's Subject Distinguisher Name. */
    CA_RENAMING,
    /** Modification of a Certificate Authority. */
    CA_EDITING,
    /** Certificate Authority generation of a new key pair that can be activated. */
    CA_KEYGEN,
    /** Certificate Authority activation of a new key pair that was generated previously and ready for activation. */
    CA_KEYACTIVATE,
    /** Certificate Authority state change to start serving requests. Unrelated to CA private key availability. */
    CA_SERVICEACTIVATE,
    /** Certificate Authority state change to stop serving requests. Unrelated to CA private key availability. */
    CA_SERVICEDEACTIVATE,
    /** Persistence of a certificate to the database. */
    CERT_STORED,
    /** Change of a certificate's status to revoked or active. */
    CERT_REVOKED,
    /** Change of a certificate's status to unassigned, inactive, active, notified about expiration, revoked or archived. */
    CERT_CHANGEDSTATUS,
    /** A request for certificate issuance from a Certificate Authority is submitted. */
    CERT_REQUEST,
    /** A certificate from a Certificate Authority is issued. */
    CERT_CREATION,
    /** Certificate Transparency log server(s) responds to a pre-certificate submission from a Certificate Authority. */
    CERT_CTPRECERT_SUBMISSION,
    /** <i>Event type is not used in EJBCA.</i> */
    CERTIFICATE_KEY_BIND,
    /** <i>Event type is not used in EJBCA.</i> */
    CERTIFICATE_KEY_UNBIND,
    /** Creation of a certificate profile. */
    CERTPROFILE_CREATION,
    /** Removal of a certificate profile. */
    CERTPROFILE_DELETION,
    /** Name change of a certificate profile. */
    CERTPROFILE_RENAMING,
    /** Modification of a certificate profile. */
    CERTPROFILE_EDITING,
    CRL_STORED,
    CRL_DELETED,
    CRL_CREATION,
    CRYPTOTOKEN_CREATE,
    CRYPTOTOKEN_EDIT,
    CRYPTOTOKEN_DELETION,
    CRYPTOTOKEN_ACTIVATION,
    CRYPTOTOKEN_DEACTIVATION,
    CRYPTOTOKEN_DELETE_ENTRY,
    CRYPTOTOKEN_GEN_KEYPAIR,
    CRYPTOTOKEN_GEN_KEY,
    CRYPTOTOKEN_GEN_EXTRACT_KEYPAIR,
    CRYPTOTOKEN_UPDATEPIN,
    LOG_DELETE,
    LOG_EXPORT,
    LOG_MANAGEMENT_CHANGE,
    LOG_SIGN,
    LOG_VERIFY,
    ROLE_CREATION,
    ROLE_DELETION,
    ROLE_RENAMING,
    ROLE_ACCESS_RULE_ADDITION,
    ROLE_ACCESS_RULE_CHANGE,
    ROLE_ACCESS_RULE_DELETION,
    ROLE_ACCESS_USER_ADDITION,
    ROLE_ACCESS_USER_CHANGE,
    ROLE_ACCESS_USER_DELETION,
    SYSTEMCONF_CREATE,
    SYSTEMCONF_EDIT,
    /** <i>Event type is not used in EJBCA.</i> */
    BACKUP,
    /** <i>Event type is not used in EJBCA.</i> */
    RESTORE,
    /** <i>Event type is not used in EJBCA.</i> */
    TIME_SYNC_ACQUIRE,
    /** <i>Event type is not used in EJBCA.</i> */
    TIME_SYNC_LOST,
    INTERNALKEYBINDING_CREATE,
    INTERNALKEYBINDING_EDIT,
    INTERNALKEYBINDING_DELETE,
    ;

    @Override
    public boolean equals(EventType value) {
        if(value == null) {
            return false;
        }
        return this.toString().equals(value.toString());
    }
}
