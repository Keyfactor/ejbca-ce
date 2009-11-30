package org.ejbca.core;

import java.io.Serializable;

/**
 * The error code describes the cause of an EjbcaException.
 * 
 * @author David Galichet.
 * @version $Id$
 */
public class ErrorCode implements Serializable {

    private static final long serialVersionUID = -5727877733175038546L;

    /** Internal error code. */
    private String internalErrorCode = _NOT_SPECIFIED;

    private static final String _CA_NOT_EXISTS = "CA_NOT_EXISTS"; // CA doesn't exists.
    private static final String _CA_ID_EQUALS_ZERO = "CA_ID_EQUALS_ZERO"; // CA ID can't be equal to zero.
    private static final String _EE_PROFILE_NOT_EXISTS = "EE_PROFILE_NOT_EXISTS"; // End Entity profile doesn't exists.
    private static final String _CERT_PROFILE_NOT_EXISTS = "CERT_PROFILE_NOT_EXISTS"; // Certificate profile doesn't exists.
    private static final String _HARD_TOKEN_ISSUER_NOT_EXISTS = "HARD_TOKEN_ISSUER_NOT_EXISTS"; // Hard token issuer doens't exists.
    private static final String _HARD_TOKEN_NOT_EXISTS = "HARD_TOKEN_NOT_EXISTS"; // Hard token doesn't exists.
    private static final String _UNKOWN_TOKEN_TYPE = "UNKOWN_TOKEN_TYPE"; // Unknown token type.
    private static final String _AUTH_CERT_NOT_RECEIVED = "AUTH_CERT_NOT_RECEIVED"; // Client authentication certificate not received.
    private static final String _USER_NOT_FOUND = "USER_NOT_FOUND"; // User doesn't exist.
    private static final String _BAD_USER_TOKEN_TYPE = "BAD_USER_TOKEN_TYPE"; // Wrong token type for user.
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
    private static final String _APPROVAL_REQUEST_ID_NOT_EXIST = "APPROVAL_REQUEST_ID_NOT_EXIST"; // Approval request with specified ID doesn't exists.
    private static final String _INVALID_LOG_LEVEL = "INVALID_LOG_LEVEL"; // Invalid custom log level.
    private static final String _INTERNAL_ERROR = "INTERNAL_ERROR"; // Technical problem.
    private static final String _NOT_SPECIFIED = "NOT_SPECIFIED"; // No error code specified.
    private static final String _CA_OFFLINE = "CA_OFFLINE"; // CA is offline.
    private static final String _ALREADY_REVOKED ="ALREADY_REVOKED"; // End entity is already revoked

    /** Default constructor. */
    private ErrorCode() {}

    /** Constructor.
     * @param errorCode error code.
     */
    private ErrorCode(String internalErrorCode) {
        this.internalErrorCode = internalErrorCode;
    }

    /** CA doesn't exists. */
    public static final ErrorCode CA_NOT_EXISTS = new ErrorCode(_CA_NOT_EXISTS);
    /** CA ID can't be equal to zero. */
    public static final ErrorCode CA_ID_EQUALS_ZERO = new ErrorCode(_CA_ID_EQUALS_ZERO);
    /** End Entity profile doesn't exists. */
    public static final ErrorCode EE_PROFILE_NOT_EXISTS = new ErrorCode(_EE_PROFILE_NOT_EXISTS);
    /** Certificate profile doesn't exists. */
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
    /** Approval request with specified ID doesn't exists. */
    public static final ErrorCode APPROVAL_REQUEST_ID_NOT_EXIST = new ErrorCode(_APPROVAL_REQUEST_ID_NOT_EXIST);
    /** Invalid custom log level. */
    public static final ErrorCode INVALID_LOG_LEVEL = new ErrorCode(_INVALID_LOG_LEVEL);
    /** Technical problem. */
    public static final ErrorCode INTERNAL_ERROR = new ErrorCode(_INTERNAL_ERROR);
    /** No error code specified. */
    public static final ErrorCode NOT_SPECIFIED = new ErrorCode(_NOT_SPECIFIED);
    /** CA is offline. */
    public static final ErrorCode CA_OFFLINE = new ErrorCode(_CA_OFFLINE);
    /** End entity is already revoked. */
    public static final ErrorCode  ALREADY_REVOKED = new ErrorCode(_ALREADY_REVOKED);

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