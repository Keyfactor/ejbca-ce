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

import org.cesecore.certificates.ca.CADoesntExistsException;
import org.cesecore.certificates.ca.CAOfflineException;
import org.cesecore.certificates.ca.IllegalNameException;
import org.cesecore.certificates.ca.IllegalValidityException;
import org.cesecore.certificates.ca.InvalidAlgorithmException;
import org.cesecore.certificates.certificate.CertificateCreateException;
import org.cesecore.certificates.certificate.CertificateRevokeException;
import org.cesecore.certificates.certificate.exception.CertificateSerialNumberException;
import org.cesecore.certificates.certificateprofile.CertificateProfileDoesNotExistException;
import org.cesecore.certificates.certificatetransparency.CTLogException;
import org.cesecore.keys.token.CryptoTokenOfflineException;
import org.ejbca.core.ejb.ra.EndEntityExistsException;

/**
 * A wrapper class to map a CesecoreException to its Enum representation to simplify the decision logic.
 *
 * @version $Id: CesecoreExceptionClasses.java 28962 2018-05-21 06:54:45Z andrey_s_helmes $
 */
public enum CesecoreExceptionClasses {

    // 400
    CertificateRevokeException(CertificateRevokeException.class),
    CertificateSerialNumberException(CertificateSerialNumberException.class),
    EndEntityExistsException(EndEntityExistsException.class),
    // 404
    CADoesntExistsException(CADoesntExistsException.class),
    CertificateProfileDoesNotExistException(CertificateProfileDoesNotExistException.class),
    NoSuchEndEntityException(org.ejbca.core.ejb.ra.NoSuchEndEntityException.class),
    // 422
    IllegalNameException(IllegalNameException.class),
    IllegalValidityException(IllegalValidityException.class),
    InvalidAlgorithmException(InvalidAlgorithmException.class),
    // 500
    CertificateCreateException(CertificateCreateException.class),
    // 503
    CAOfflineException(CAOfflineException.class),
    CryptoTokenOfflineException(CryptoTokenOfflineException.class),
    CTLogException(CTLogException.class),
    // All others
    UNKNOWN(null);

    CesecoreExceptionClasses(Class<?> targetClass) {
        ExceptionClassHolder.map.put(targetClass, this);
    }

    /**
     * Returns an exemplar of this enum.
     *
     * @param clazz A class.
     *
     * @return exemplar of this enum.
     */
    public static CesecoreExceptionClasses fromClass(Class<?> clazz) {
        CesecoreExceptionClasses cesecoreExceptionClasses = ExceptionClassHolder.map.get(clazz);
        return cesecoreExceptionClasses != null ? cesecoreExceptionClasses : UNKNOWN;
    }

    private static class ExceptionClassHolder {
        public static final IdentityHashMap<Class<?>, CesecoreExceptionClasses> map = new IdentityHashMap<>();
    }
}
