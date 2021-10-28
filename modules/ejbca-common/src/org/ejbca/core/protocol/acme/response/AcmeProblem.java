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
package org.ejbca.core.protocol.acme.response;

/**
 * Enumeration of ACME problem types.
 * 
 * @see https://tools.ietf.org/html/rfc8555#section-6.7
 */
public enum AcmeProblem {
    PROBLEM_BAD_CSR("badCSR", "The CSR is unacceptable (e.g., due to a short key)"),
    PROBLEM_BAD_NONCE("badNonce", "The client sent an unacceptable anti-replay nonce"),
    PROBLEM_BAD_SIGNATURE_ALGORITHM("badSignatureAlgorithm",
                    "The JWS was signed with an algorithm the server does not support"),
    PROBLEM_UNSUPPORTED_CONTACT("unsupportedContact", "The contact URL scheme is not supported. Use 'mailto'"),
    PROBLEM_INVALID_CONTACT("invalidContact", "The contact URI for an account was invalid"),
    PROBLEM_MALFORMED("malformed", "The request message was malformed"),
    PROBLEM_RATE_LIMITED("rateLimited", "The request exceeds a rate limit"),
    PROBLEM_REJECTED_INDENTIFIER("rejectedIdentifier", "The server will not issue certificate for the identifier"),
    PROBLEM_SERVER_INTERNAL("serverInternal", "The server experienced an internal error"),
    PROBLEM_UNAUTHORIZED("unauthorized", "The client lacks sufficient authorization"),
    PROBLEM_UNSUPPORTED_INDENTIFIER("unsupportedIdentifier", "Identifier is not supported, but may be in future"),
    PROBLEM_USER_ACTION_REQUIRED("userActionRequired", "Visit the \"instance\" URL and take actions specified there"),
    PROBLEM_ALREADY_REVOKED("alreadyRevoked", "The certificate is already revoked."),
    PROBLEM_BAD_REVOCATION_REASON("badRevocationReason", "The revocation reason provided is not allowed by the server"),
    PROBLEM_CAA("caa", "CAA records forbid the CA from issuing"),
    PROBLEM_DNS("dns", "There was a problem with a DNS query"),
    PROBLEM_CONNECTION("connection", "The server could not connect to validation target"),
    PROBLEM_TLS("tls", "The server received a TLS error during validation"),
    PROBLEM_INCORRECT_RESPONSE("incorrectResponse", "Response received didn't match the challenge's requirements"),
    PROBLEM_ACCOUNT_DOES_NOT_EXIST("accountDoesNotExist", "The request specified an account that does not exist"),
    PROBLEM_ORDER_NOT_READY("orderNotReady", "Order is not ready yet."),
    PROBLEM_EXTERNAL_ACCOUNT_REQUIRED("externalAccountRequired", "External account binding required."),
    PROBLEM_APPROVAL_REQUIRED_FOR_ACCOUNT_REGISTRATION("approvalRequiredForAccountRegistration", "Account registration requires the approval of one or more administrators."),
    PROBLEM_APPROVAL_REQUIRED_FOR_ACCOUNT_KEY_CHANGE("approvalRequiredForKeyChange", "Key change requires the approval of one or more administrators.");
        
    private final String type;
    private final String detail;

    private AcmeProblem(final String subType, final String description) {
        this.type = "urn:ietf:params:acme:error:" + subType;
        this.detail = description;
    }

    public String getType() {
        return type;
    }

    public String getDetail() {
        return detail;
    }

}
