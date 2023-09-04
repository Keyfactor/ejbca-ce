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

import javax.ejb.EJB;
import javax.ejb.Stateless;
import javax.ejb.TransactionAttribute;
import javax.ejb.TransactionAttributeType;

import org.cesecore.certificates.ca.CAInfo;
import org.cesecore.certificates.endentity.EndEntityInformation;
import org.cesecore.jndi.JndiConstants;

/**
 */
@Stateless(mappedName = JndiConstants.APP_JNDI_PREFIX + "InternalCertificateCreateSessionRemote")
@TransactionAttribute(TransactionAttributeType.REQUIRED)
public class InternalCertificateCreateSessionBean implements InternalCertificateCreateSessionRemote {

    @EJB
    private CertificateCreateSessionLocal certificateCreateSession;
    
    @Override
    public void assertSubjectEnforcements(CAInfo caInfo, EndEntityInformation endEntityInformation) throws CertificateCreateException {
        certificateCreateSession.assertSubjectEnforcements(caInfo, endEntityInformation);
    }

   
}
