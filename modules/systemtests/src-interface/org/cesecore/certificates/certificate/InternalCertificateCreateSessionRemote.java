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

import javax.ejb.Remote;

import org.cesecore.certificates.ca.CAInfo;
import org.cesecore.certificates.endentity.EndEntityInformation;

/**
 * Testing bean to make methods in CertificateCreateSessionLocal available for tests
 */
@Remote
public interface InternalCertificateCreateSessionRemote {

    /**
     * Performs SubjectDN checks
     * @param caInfo non-sensitive information
     * @param endEntityInformation user data
     * @throws CertificateCreateException if the certificate couldn't be created. 
     */
    void assertSubjectEnforcements(CAInfo caInfo, EndEntityInformation endEntityInformation) throws CertificateCreateException;

}
