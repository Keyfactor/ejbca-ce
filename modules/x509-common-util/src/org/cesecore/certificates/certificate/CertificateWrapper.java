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
package org.cesecore.certificates.certificate;

import java.io.Serializable;
import java.security.cert.Certificate;

/**
 * General interface for any object that wraps a certificate, such as
 * {@link CertificateDataWrapper} and {@link CertificateSerializableWrapper}.
 * 
 * Implementations of this interface are expected to handle (de-)serialization of certificates
 * from the BouncyCastle provider. E.g. having a transient Certificate object and
 * having an encoded certificate that is actually serialized.
 *
 * @see org.cesecore.util.EJBTools
 * 
 * @version $Id$
 */
public interface CertificateWrapper extends Serializable {

    Certificate getCertificate();
    
}
