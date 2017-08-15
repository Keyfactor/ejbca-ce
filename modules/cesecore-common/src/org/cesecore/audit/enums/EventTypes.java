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
 * @see org.cesecore.audit.enums.ModuleTypes
 * @see org.cesecore.audit.enums.ServiceTypes
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
    /** Certificate Authority starts using a different key pair. */
    CA_KEYACTIVATE,
    /** Generation of a new key pair that can be used by the Certificate Authority during renewal or update. */
    CA_KEYGEN,
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
    /** Issuance of a certificate by a Certificate Authority. */
    CERT_CREATION,
    /** Certificate Transparency log servers responds to a pre-certificate submission from a Certificate Authority. */
    CERT_CTPRECERT_SUBMISSION,
    /** <i>Event type is currently not used in EJBCA.</i> */
    CERTIFICATE_KEY_BIND,
    /** <i>Event type is currently not used in EJBCA.</i> */
    CERTIFICATE_KEY_UNBIND,
    /** Creation of a certificate profile. */
    CERTPROFILE_CREATION,
    /** Removal of a certificate profile. */
    CERTPROFILE_DELETION,
    /** Name change of a certificate profile. */
    CERTPROFILE_RENAMING,
    /** Modification of a certificate profile. */
    CERTPROFILE_EDITING,
    /** Persistence of a Certificate Revocation List to the database. */
    CRL_STORED,
    /** <i>Event type is currently not used in EJBCA.</i> */
    CRL_DELETED,
    /** Issuance of a Certificate Revocation List by a Certificate Authority. */
    CRL_CREATION,
    /** Creation of a Crypto Token. */
    CRYPTOTOKEN_CREATE,
    /** Modification of a Crypto Token. */
    CRYPTOTOKEN_EDIT,
    /** Removal of a Crypto Token. */
    CRYPTOTOKEN_DELETION,
    /** Activation of a Crypto Token, making the key material available for use by the application. */
    CRYPTOTOKEN_ACTIVATION,
    /** Deactivation of a Crypto Token, making the key material unavailable for use by the application. */
    CRYPTOTOKEN_DEACTIVATION,
    /** Attempted reactivation of a Crypto Token. Since this occurs automatically, it may fail. */
    CRYPTOTOKEN_REACTIVATION,
    /** Removal of a key pair from the Crypto Token key material or key pair place-holder from the Crypto Token object. */
    CRYPTOTOKEN_DELETE_ENTRY,
    /** Generation of a new key pair in the Crypto Token. */
    CRYPTOTOKEN_GEN_KEYPAIR,
    /** <i>Event type is currently not used in EJBCA.</i> */
    CRYPTOTOKEN_GEN_KEY,
    /** <i>Event type is currently not used in EJBCA.</i> */
    CRYPTOTOKEN_GEN_EXTRACT_KEYPAIR,
    /** Modification of the Crypto Token's auto-activation PIN. For soft key stores, this also implies changes of the protection of the key material. */
    CRYPTOTOKEN_UPDATEPIN,
    /** Modification of an existing validator. */
    VALIDATOR_CHANGE,
    /** Creation of a new validator. */
    VALIDATOR_CREATION,
    /** Removal of an existing validator. */
    VALIDATOR_REMOVAL,
    /** Name change of an existing validator. */
    VALIDATOR_RENAME,
    /** Validation failed. */
    VALIDATOR_VALIDATION_FAILED,
    /** Removal of persisted audit log records. */
    LOG_DELETE,
    /** Export of audit log records. */
    LOG_EXPORT,
    /** Change of protection settings for audit log records. */
    LOG_MANAGEMENT_CHANGE,
    /** <i>Event type is currently only used by EJBCA development tests.</i> */
    LOG_SIGN,
    /** Verification of existing audit log records. */
    LOG_VERIFY,
    /** Creation of an administrative role. */
    ROLE_CREATION,
    /** Removal of an administrative role. */
    ROLE_DELETION,
    /** Name change of an administrative role. */
    ROLE_RENAMING,
    /** New access rules added to administrative role. */
    @Deprecated // Also msg key authorization.accessrulesadded
    ROLE_ACCESS_RULE_ADDITION,
    /** Modifications of existing access rules in an administrative role. */
    ROLE_ACCESS_RULE_CHANGE,
    /** Removal of existing access rules from administrative role. */
    @Deprecated // Also msg key authorization.accessrulesremoved
    ROLE_ACCESS_RULE_DELETION,
    /** New administrator added to administrative role. */
    ROLE_ACCESS_USER_ADDITION,
    /** Change of existing administrator in an administrative role. */
    ROLE_ACCESS_USER_CHANGE,
    /** Removal of existing administrator from administrative role. */
    ROLE_ACCESS_USER_DELETION,
    /** Creation of new system settings stored in the database. */
    SYSTEMCONF_CREATE,
    /** Modification of existing system settings stored in the database. */
    SYSTEMCONF_EDIT,
    /** <i>Event type is currently not used in EJBCA.</i> */
    BACKUP,
    /** <i>Event type is currently not used in EJBCA.</i> */
    RESTORE,
    /** <i>Event type is currently not used in EJBCA.</i> */
    TIME_SYNC_ACQUIRE,
    /** <i>Event type is currently not used in EJBCA.</i> */
    TIME_SYNC_LOST,
    /** Creations of a new Internal Key Binding. */
    INTERNALKEYBINDING_CREATE,
    /** Modification of an existing Internal Key Binding. */
    INTERNALKEYBINDING_EDIT,
    /** Removal of an existing Internal Key Binding. */
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
