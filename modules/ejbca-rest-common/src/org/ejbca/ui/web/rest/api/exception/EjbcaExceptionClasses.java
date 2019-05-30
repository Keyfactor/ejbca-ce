/*************************************************************************
 *                                                                       *
 *  EJBCA - Proprietary Modules: Enterprise Certificate Authority        *
 *                                                                       *
 *  Copyright (c), PrimeKey Solutions AB. All rights reserved.           *
 *  The use of the Proprietary Modules are subject to specific           * 
 *  commercial license terms.                                            *
 *                                                                       *
 *************************************************************************/
package org.ejbca.ui.web.rest.api.exception;

import java.util.IdentityHashMap;

import org.ejbca.core.model.approval.ApprovalException;
import org.ejbca.core.model.ca.AuthLoginException;
import org.ejbca.core.model.ca.AuthStatusException;
import org.ejbca.core.model.ra.AlreadyRevokedException;
import org.ejbca.core.model.ra.CustomFieldException;
import org.ejbca.core.model.ra.EndEntityProfileValidationRaException;
import org.ejbca.core.model.ra.KeyStoreGeneralRaException;
import org.ejbca.core.model.ra.NotFoundException;
import org.ejbca.core.model.ra.RevokeBackDateNotAllowedForProfileException;

/**
 * A wrapper class to map an EjbcaException to its Enum representation to simplify the decision logic.
 *
 * @version $Id: EjbcaExceptionClasses.java 28962 2018-05-18 06:54:45Z andrey_s_helmes $
 */
public enum EjbcaExceptionClasses {

    // 400
    ApprovalException(ApprovalException.class),
    KeyStoreGeneralRaException(KeyStoreGeneralRaException.class),
    // 403
    AuthLoginException(AuthLoginException.class),
    AuthStatusException(AuthStatusException.class),
    // 404
    NotFoundException(NotFoundException.class),
    // 409
    AlreadyRevokedException(AlreadyRevokedException.class),
    // 422
    // TODO These exception cannot be found in compilation classpath
//    WrongTokenTypeException(WrongTokenTypeException.class),
//    CertificateProfileTypeNotAcceptedException(CertificateProfileTypeNotAcceptedException.class),
    CustomFieldException(CustomFieldException.class),
    EndEntityProfileValidationRaException(EndEntityProfileValidationRaException.class),
    RevokeBackDateNotAllowedForProfileException(RevokeBackDateNotAllowedForProfileException.class),
    // 500
    // 503
    // All others
    UNKNOWN(null);

    EjbcaExceptionClasses(Class<?> targetClass) {
        ExceptionClassHolder.map.put(targetClass, this);
    }

    /**
     * Returns an exemplar of this enum.
     *
     * @param clazz A class.
     *
     * @return exemplar of this enum.
     */
    public static EjbcaExceptionClasses fromClass(Class<?> clazz) {
        EjbcaExceptionClasses ejbcaExceptionClasses = ExceptionClassHolder.map.get(clazz);
        return ejbcaExceptionClasses != null ? ejbcaExceptionClasses : UNKNOWN;
    }

    private static class ExceptionClassHolder {
        public static final IdentityHashMap<Class<?>, EjbcaExceptionClasses> map = new IdentityHashMap<>();
    }
}
