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
package org.ejbca.ui.web.rest.api.exception;

import java.security.cert.CertificateEncodingException;
import java.util.IdentityHashMap;

import org.cesecore.authentication.AuthenticationFailedException;
import org.cesecore.authorization.AuthorizationDeniedException;
import org.cesecore.certificates.certificate.certextensions.CertificateExtensionException;
import org.cesecore.roles.RoleExistsException;
import org.cesecore.roles.RoleNotFoundException;
import org.ejbca.core.model.approval.AdminAlreadyApprovedRequestException;
import org.ejbca.core.model.approval.ApprovalRequestExecutionException;
import org.ejbca.core.model.approval.ApprovalRequestExpiredException;
import org.ejbca.core.model.approval.SelfApprovalException;
import org.ejbca.core.model.approval.WaitingForApprovalException;
import org.ejbca.core.model.ra.raadmin.EndEntityProfileNotFoundException;
import org.ejbca.core.model.ra.raadmin.EndEntityProfileValidationException;
import org.ejbca.core.model.ra.raadmin.UserDoesntFullfillEndEntityProfile;

import com.keyfactor.util.StreamSizeLimitExceededException;

/**
 * A wrapper class to map a Standalone Exception to its Enum representation to simplify the decision logic.
 *
 * @version $Id: ExceptionClasses.java 28962 2018-05-18 06:54:45Z andrey_s_helmes $
 */
public enum ExceptionClasses {

    // 202
    WaitingForApprovalException(WaitingForApprovalException.class),
    // 400
    ApprovalRequestExecutionException(ApprovalRequestExecutionException.class),
    ApprovalRequestExpiredException(ApprovalRequestExpiredException.class),
    RoleExistsException(RoleExistsException.class),
    // 403
    AuthenticationFailedException(AuthenticationFailedException.class),
    AuthorizationDeniedException(AuthorizationDeniedException.class),
    SelfApprovalException(SelfApprovalException.class),
    // 404
    EndEntityProfileNotFoundException(EndEntityProfileNotFoundException.class),
    RoleNotFoundException(RoleNotFoundException.class),
    // 409
    AdminAlreadyApprovedRequestException(AdminAlreadyApprovedRequestException.class),
    // 413
    StreamSizeLimitExceededException(StreamSizeLimitExceededException.class),
    // 422
    EndEntityProfileValidationException(EndEntityProfileValidationException.class),
    UserDoesntFullfillEndEntityProfile(UserDoesntFullfillEndEntityProfile.class),
    CertificateExtensionException(CertificateExtensionException.class),
    // 500
    CertificateEncodingException(CertificateEncodingException.class),

    // All others
    UNKNOWN(null);

    ExceptionClasses(Class<?> targetClass) {
        ExceptionClassHolder.map.put(targetClass, this);
    }

    /**
     * Returns an exemplar of this enum.
     *
     * @param clazz A class.
     *
     * @return exemplar of this enum.
     */
    public static ExceptionClasses fromClass(Class<?> clazz) {
        ExceptionClasses internalExceptionClasses = ExceptionClassHolder.map.get(clazz);
        return internalExceptionClasses != null ? internalExceptionClasses : UNKNOWN;
    }

    private static class ExceptionClassHolder {
        public static final IdentityHashMap<Class<?>, ExceptionClasses> map = new IdentityHashMap<>();
    }
}
