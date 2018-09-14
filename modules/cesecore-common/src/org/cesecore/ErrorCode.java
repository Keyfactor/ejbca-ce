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
package org.cesecore;

import java.io.Serializable;

/**
 * The error code describes the cause of an EjbcaException.
 * Usage:
 * <pre>
 * (caught EjbcaException e)
 * If (e.equals(ErrorCode.SIGNATURE_ERROR) {
 *     System.out.println("Error verifying signature (popp) of request");
 * }
 * </pre>
 * 
 * @version $Id$
 */
public class ErrorCode implements Serializable {

    private static final long serialVersionUID = -5727877733175038546L;

    /** Internal error code. */
    private String internalErrorCode = _NOT_SPECIFIED;

    private static final String _CA_NOT_EXISTS = "CA_NOT_EXISTS"; // CA does not exist.
    private static final String _CA_ALREADY_EXISTS = "CA_ALREADY_EXISTS"; // CA already exists.
    private static final String _CA_ID_EQUALS_ZERO = "CA_ID_EQUALS_ZERO"; // CA ID can't be equal to zero.
    private static final String _EE_PROFILE_NOT_EXISTS = "EE_PROFILE_NOT_EXISTS"; // End Entity profile does not exist.
    private static final String _CERT_PROFILE_NOT_EXISTS = "CERT_PROFILE_NOT_EXISTS"; // Certificate profile does not exist.
    private static final String _HARD_TOKEN_ISSUER_NOT_EXISTS = "HARD_TOKEN_ISSUER_NOT_EXISTS"; // Hard token issuer doens't exists.
    private static final String _HARD_TOKEN_NOT_EXISTS = "HARD_TOKEN_NOT_EXISTS"; // Hard token does not exist.
    private static final String _UNKOWN_TOKEN_TYPE = "UNKOWN_TOKEN_TYPE"; // Unknown token type.
    private static final String _AUTH_CERT_NOT_RECEIVED = "AUTH_CERT_NOT_RECEIVED"; // Client authentication certificate not received.
    private static final String _USER_NOT_FOUND = "USER_NOT_FOUND"; // User doesn't exist.
    private static final String _BAD_USER_TOKEN_TYPE = "BAD_USER_TOKEN_TYPE"; // Wrong token type for user.
    private static final String _INVALID_CERTIFICATE = "INVALID_CERTIFICATE"; // Generated certificate is invalid (usually validated with external command).
    private static final String _INVALID_KEY = "INVALID_KEY"; // Provided key is invalid.
    private static final String _ILLEGAL_KEY = "ILLEGAL_KEY"; // User key is illegal (key length too small).
    private static final String _USER_WRONG_STATUS = "USER_WRONG_STATUS"; // User wrong status.
    private static final String _USER_ALREADY_EXISTS = "USER_ALREADY_EXISTS"; // User already exists
    private static final String _LOGIN_ERROR = "LOGIN_ERROR"; // Login error.
    private static final String _SIGNATURE_ERROR = "SIGNATURE_ERROR"; // Error in signature.
    private static final String _INVALID_KEY_SPEC = "INVALID_KEY_SPEC"; // Invalid key specification.
    private static final String _CERT_WRONG_STATUS = "CERT_WRONG_STATUS"; // Certificate wrong status.
    private static final String _KEY_RECOVERY_NOT_AVAILABLE = "KEY_RECOVERY_NOT_AVAILABLE"; // Key recovery feature not enabled.
    private static final String _BAD_VALIDITY_FORMAT = "BAD_VALIDITY_FORMAT"; // Validity format badly formatted (must be defined in days).
    private static final String _NOT_SUPPORTED_KEY_STORE = "NOT_SUPPORTED_KEY_STORE"; // Key store type not supported.
    private static final String _NOT_SUPPORTED_REQUEST_TYPE = "NOT_SUPPORTED_REQUEST_TYPE"; // Not supported request type.
    private static final String _NOT_SUPPORTED_PIN_TYPE = "NOT_SUPPORTED_PIN_TYPE"; // Not supported PIN type.
    private static final String _NOT_SUPPORTED_TOKEN_TYPE = "NOT_SUPPORTED_TOKEN_TYPE"; // Not supported token type.
    private static final String _NOT_AUTHORIZED = "NOT_AUTHORIZED"; // Authorization denied.
    private static final String _APPROVAL_WRONG_STATUS = "APPROVAL_WRONG_STATUS"; // Wrong status of approval.
    private static final String _ENOUGH_APPROVAL = "ENOUGH_APPROVAL"; // Already enough approval for this request.
    private static final String _APPROVAL_ALREADY_EXISTS = "APPROVAL_ALREADY_EXISTS"; // Approval already exists.
    private static final String _APPROVAL_REQUEST_ID_NOT_EXIST = "APPROVAL_REQUEST_ID_NOT_EXIST"; // Approval request with specified ID does not exist.
    private static final String _INVALID_LOG_LEVEL = "INVALID_LOG_LEVEL"; // Invalid custom log level.
    private static final String _INTERNAL_ERROR = "INTERNAL_ERROR"; // Technical problem.
    private static final String _NOT_SPECIFIED = "NOT_SPECIFIED"; // No error code specified.
    private static final String _CA_OFFLINE = "CA_OFFLINE"; // CA is offline.
    private static final String _CA_INVALID_TOKEN_PIN = "CA INVALID TOKEN PIN"; // an invalid CA token PIN was given
    private static final String _ALREADY_REVOKED ="ALREADY_REVOKED"; // End entity is already revoked
    private static final String _CERT_PATH_INVALID ="CERT_PATH_INVALID"; // A certificate path was invalid/could not be constructed
    private static final String _CERT_COULD_NOT_BE_PARSED = "CERT_COULD_NOT_BE_PARSED"; // Certificates in a PEM or DER file could not be parsed.
    private static final String _CERTIFICATE_FOR_THIS_KEY_ALREADY_EXISTS_FOR_ANOTHER_USER="CERTIFICATE_FOR_THIS_KEY_ALREADY_EXISTS_FOR_ANOTHER_USER";
	private static final String _CERTIFICATE_WITH_THIS_SUBJECTDN_ALREADY_EXISTS_FOR_ANOTHER_USER = "CERTIFICATE_WITH_THIS_SUBJECTDN_ALREADY_EXISTS_FOR_ANOTHER_USER";
	private static final String _SUBJECTDN_SERIALNUMBER_ALREADY_EXISTS = "SUBJECTDN_SERIALNUMBER_ALREADY_EXISTS";
	private static final String _FIELD_VALUE_NOT_VALID = "_FIELD_VALUE_NOT_VALID";
	private static final String _REVOKE_BACKDATE_NOT_ALLOWED = "REVOKE_BACKDATE_NOT_ALLOWED";
	private static final String _DATE_NOT_VALID = "DATE_NOT_VALID";
	private static final String _CRYPTOTOKEN_NAME_IN_USE = "CRYPTOTOKEN_NAME_IN_USE"; // A CryptoToken with the name already exists
    private static final String _INTERNAL_KEY_BINDING_NAME_IN_USE = "INTERNAL_KEY_BINDING_NAME_IN_USE"; // An InternalKeyBinding with the name already exists
    private static final String _CERTIFICATE_IMPORT = "CERTIFICATE_IMPORT"; // Failure during import of a certificate
    private static final String _NAMECONSTRAINT_VIOLATION = "NAMECONSTRAINT_VIOLATION"; // End-entity does not satisfy name constraints of CA
    private static final String _UNKNOWN_PROFILE_TYPE = "UNKNOWN_PROFILE_TYPE"; // The profile type is neither end entity profile nor certificate profile
    private static final String _UNSUPPORTED_METHOD = "UNSUPPORTED_METHOD"; // Typically used to block access to enterprise-only features
    private static final String _SIGNED_BY_EXTERNAL_CA_NOT_SUPPORTED = "SIGNED_BY_EXTERNAL_CA_NOT_SUPPORTED"; // when trying to create a new CA signed by an external CA using the WS
    private static final String _BAD_CERTIFICATE_PROFILE_TYPE = "BAD_CERTIFICATE_PROFILE_TYPE"; // when using a cert/endentity profile of the wrong type
    private static final String _ROLE_DOES_NOT_EXIST = "ROLE_DOES_NOT_EXIST"; // When trying to find a role that does not exist
    private static final String _BAD_REQUEST_SIGNATURE = "BAD_REQUEST_SIGNATURE"; // Failure to verify request signature.
    private static final String _CA_NAME_CHANGE_RENEWAL_ERROR = "CA_NAME_CHANGE_RENEWAL_ERROR"; // CA Name Change Renewal could not be completed
    private static final String _USER_DOESNT_FULFILL_END_ENTITY_PROFILE = "USER_DOESNT_FULFILL_END_ENTITY_PROFILE"; // User could not be added cause it doesn't fulfill end entity profile
    private static final String _REQUIRED_CUSTOM_CERTIFICATE_EXTENSION_MISSING = "REQUIRED_CUSTOM_CERTIFICATE_EXTENSION_MISSING";

    /** Default constructor. */
    private ErrorCode() {}

    /** Constructor.
     * @param errorCode error code.
     */
    private ErrorCode(String internalErrorCode) {
        this.internalErrorCode = internalErrorCode;
    }

    /** CA does not exist. */
    public static final ErrorCode CA_NOT_EXISTS = new ErrorCode(_CA_NOT_EXISTS);
    /** CA already exists. */
    public static final ErrorCode CA_ALREADY_EXISTS = new ErrorCode(_CA_ALREADY_EXISTS);
    /** CA ID can't be equal to zero. */
    public static final ErrorCode CA_ID_EQUALS_ZERO = new ErrorCode(_CA_ID_EQUALS_ZERO);
    /** End Entity profile does not exist. */
    public static final ErrorCode EE_PROFILE_NOT_EXISTS = new ErrorCode(_EE_PROFILE_NOT_EXISTS);
    /** Certificate profile does not exist. */
    public static final ErrorCode CERT_PROFILE_NOT_EXISTS = new ErrorCode(_CERT_PROFILE_NOT_EXISTS);
    /** Hard token issuer doens't exists. */
    public static final ErrorCode HARD_TOKEN_ISSUER_NOT_EXISTS = new ErrorCode(_HARD_TOKEN_ISSUER_NOT_EXISTS);
    /** Hard token issuer exists. */
    public static final ErrorCode HARD_TOKEN_NOT_EXISTS = new ErrorCode(_HARD_TOKEN_NOT_EXISTS);
    /** Unknown token type. */
    public static final ErrorCode UNKOWN_TOKEN_TYPE = new ErrorCode(_UNKOWN_TOKEN_TYPE);
    /** Client authentication certificate not received. */
    public static final ErrorCode AUTH_CERT_NOT_RECEIVED = new ErrorCode(_AUTH_CERT_NOT_RECEIVED);
    /** User doesn't exist. */
    public static final ErrorCode USER_NOT_FOUND = new ErrorCode(_USER_NOT_FOUND);
    /** Wrong token type for user. */
    public static final ErrorCode BAD_USER_TOKEN_TYPE = new ErrorCode(_BAD_USER_TOKEN_TYPE);
    /** Generated certificate is invalid. */
    public static final ErrorCode INVALID_CERTIFICATE = new ErrorCode(_INVALID_CERTIFICATE);
    /** Provided key is invalid. */
    public static final ErrorCode INVALID_KEY = new ErrorCode(_INVALID_KEY);
    /** User key is illegal (key length too small). */
    public static final ErrorCode ILLEGAL_KEY = new ErrorCode(_ILLEGAL_KEY);
    /** User wrong status. */
    public static final ErrorCode USER_WRONG_STATUS = new ErrorCode(_USER_WRONG_STATUS);
    /** User already exists. */
    public static final ErrorCode USER_ALREADY_EXISTS = new ErrorCode(_USER_ALREADY_EXISTS);
    /** Login error. */
    public static final ErrorCode LOGIN_ERROR = new ErrorCode(_LOGIN_ERROR);
    /** Error in signature. */
    public static final ErrorCode SIGNATURE_ERROR = new ErrorCode(_SIGNATURE_ERROR);
    /** Invalid key specification. */
    public static final ErrorCode INVALID_KEY_SPEC = new ErrorCode(_INVALID_KEY_SPEC);
    /** Certificate wrong status. */
    public static final ErrorCode CERT_WRONG_STATUS = new ErrorCode(_CERT_WRONG_STATUS);
    /** Key recovery feature not enabled. */
    public static final ErrorCode KEY_RECOVERY_NOT_AVAILABLE = new ErrorCode(_KEY_RECOVERY_NOT_AVAILABLE);
    /** Validity format badly formatted (must be defined in days). */
    public static final ErrorCode BAD_VALIDITY_FORMAT = new ErrorCode(_BAD_VALIDITY_FORMAT);
    /** Key store type not supported. */
    public static final ErrorCode NOT_SUPPORTED_KEY_STORE = new ErrorCode(_NOT_SUPPORTED_KEY_STORE);
    /** Not supported request type. */
    public static final ErrorCode NOT_SUPPORTED_REQUEST_TYPE = new ErrorCode(_NOT_SUPPORTED_REQUEST_TYPE);
    /** Not supported PIN type. */
    public static final ErrorCode NOT_SUPPORTED_PIN_TYPE = new ErrorCode(_NOT_SUPPORTED_PIN_TYPE);
    /** Not supported token type. */
    public static final ErrorCode NOT_SUPPORTED_TOKEN_TYPE = new ErrorCode(_NOT_SUPPORTED_TOKEN_TYPE);
    /** Authorization denied. */
    public static final ErrorCode NOT_AUTHORIZED = new ErrorCode(_NOT_AUTHORIZED);
    /** Wrong status of approval. */
    public static final ErrorCode APPROVAL_WRONG_STATUS = new ErrorCode(_APPROVAL_WRONG_STATUS);
    /** Already enough approval for this request. */
    public static final ErrorCode ENOUGH_APPROVAL = new ErrorCode(_ENOUGH_APPROVAL);
    /** Approval already exists. */
    public static final ErrorCode APPROVAL_ALREADY_EXISTS = new ErrorCode(_APPROVAL_ALREADY_EXISTS);
    /** Approval request with specified ID does not exist. */
    public static final ErrorCode APPROVAL_REQUEST_ID_NOT_EXIST = new ErrorCode(_APPROVAL_REQUEST_ID_NOT_EXIST);
    /** Invalid custom log level. */
    public static final ErrorCode INVALID_LOG_LEVEL = new ErrorCode(_INVALID_LOG_LEVEL);
    /** Technical problem. */
    public static final ErrorCode INTERNAL_ERROR = new ErrorCode(_INTERNAL_ERROR);
    /** No error code specified. */
    public static final ErrorCode NOT_SPECIFIED = new ErrorCode(_NOT_SPECIFIED);
    /** CA is offline. */
    public static final ErrorCode CA_OFFLINE = new ErrorCode(_CA_OFFLINE);
    /** CA token PIN is invalid. */
    public static final ErrorCode CA_INVALID_TOKEN_PIN = new ErrorCode(_CA_INVALID_TOKEN_PIN);
    /** End entity is already revoked. */
    public static final ErrorCode  ALREADY_REVOKED = new ErrorCode(_ALREADY_REVOKED);
    /** A certificate path was invalid/could not be constructed. */
    public static final ErrorCode CERT_PATH_INVALID = new ErrorCode(_CERT_PATH_INVALID);
    public static final ErrorCode CERT_COULD_NOT_BE_PARSED = new ErrorCode(_CERT_COULD_NOT_BE_PARSED);
    public static final ErrorCode CERTIFICATE_FOR_THIS_KEY_ALLREADY_EXISTS_FOR_ANOTHER_USER = new ErrorCode(_CERTIFICATE_FOR_THIS_KEY_ALREADY_EXISTS_FOR_ANOTHER_USER);
	public static final ErrorCode CERTIFICATE_WITH_THIS_SUBJECTDN_ALREADY_EXISTS_FOR_ANOTHER_USER = new ErrorCode(_CERTIFICATE_WITH_THIS_SUBJECTDN_ALREADY_EXISTS_FOR_ANOTHER_USER);
	public static final ErrorCode SUBJECTDN_SERIALNUMBER_ALREADY_EXISTS = new ErrorCode(_SUBJECTDN_SERIALNUMBER_ALREADY_EXISTS);
	public static final ErrorCode FIELD_VALUE_NOT_VALID = new ErrorCode(_FIELD_VALUE_NOT_VALID);
	public static final ErrorCode REVOKE_BACKDATE_NOT_ALLOWED = new ErrorCode(_REVOKE_BACKDATE_NOT_ALLOWED);
	public static final ErrorCode DATE_NOT_VALID = new ErrorCode(_DATE_NOT_VALID);
    public static final ErrorCode CRYPTOTOKEN_NAME_IN_USE = new ErrorCode(_CRYPTOTOKEN_NAME_IN_USE);
    public static final ErrorCode INTERNAL_KEY_BINDING_NAME_IN_USE = new ErrorCode(_INTERNAL_KEY_BINDING_NAME_IN_USE);
    public static final ErrorCode CERTIFICATE_IMPORT = new ErrorCode(_CERTIFICATE_IMPORT);
    public static final ErrorCode NAMECONSTRAINT_VIOLATION = new ErrorCode(_NAMECONSTRAINT_VIOLATION);
    public static final ErrorCode UNKNOWN_PROFILE_TYPE = new ErrorCode(_UNKNOWN_PROFILE_TYPE);
    public static final ErrorCode UNSUPPORTED_METHOD = new ErrorCode(_UNSUPPORTED_METHOD);
    public static final ErrorCode SIGNED_BY_EXTERNAL_CA_NOT_SUPPORTED = new ErrorCode(_SIGNED_BY_EXTERNAL_CA_NOT_SUPPORTED);
    public static final ErrorCode BAD_CERTIFICATE_PROFILE_TYPE = new ErrorCode(_BAD_CERTIFICATE_PROFILE_TYPE);
    public static final ErrorCode ROLE_DOES_NOT_EXIST = new ErrorCode(_ROLE_DOES_NOT_EXIST);
    /** Failure to verify request signature. */
    public static final ErrorCode BAD_REQUEST_SIGNATURE = new ErrorCode(_BAD_REQUEST_SIGNATURE);
    public static final ErrorCode CA_NAME_CHANGE_RENEWAL_ERROR = new ErrorCode(_CA_NAME_CHANGE_RENEWAL_ERROR);
    public static final ErrorCode USER_DOESNT_FULFILL_END_ENTITY_PROFILE = new ErrorCode(_USER_DOESNT_FULFILL_END_ENTITY_PROFILE);
    public static final ErrorCode REQUIRED_CUSTOM_CERTIFICATE_EXTENSION_MISSING = new ErrorCode(_REQUIRED_CUSTOM_CERTIFICATE_EXTENSION_MISSING);

    /** Get the internal error code. */
    public String getInternalErrorCode() {
        return internalErrorCode;
    }

    /** Set the internal error code. */
    public void setInternalErrorCode(String internalErrorCode) {
        this.internalErrorCode = internalErrorCode;
    }

    /** @see java.lang.Object#equals(Object) */
    public boolean equals(Object obj) {
        if (obj != null && obj instanceof ErrorCode) {
            ErrorCode other = (ErrorCode) obj;
            return this.internalErrorCode.equals(other.internalErrorCode);
        } else {
            return false;
        }
    }
    /* (non-Javadoc)
     * @see java.lang.Object#toString()
     */
    public String toString() {
        return "Internal EJBCA error code: "+this.internalErrorCode;
    }
    /** @see java.lang.Object#hashCode() */
    public int hashCode() {
        if (internalErrorCode != null) {
            return internalErrorCode.hashCode();
        } else {
            return 0;
        }
    }
}