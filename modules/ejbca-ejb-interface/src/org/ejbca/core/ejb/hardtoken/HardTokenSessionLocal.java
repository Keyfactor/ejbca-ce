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
package org.ejbca.core.ejb.hardtoken;

import java.util.List;

import javax.ejb.Local;

import org.cesecore.certificates.certificate.CertificateDataWrapper;

/**
 * Local interface for HardTokenSession.
 * 
 * @version $Id$
 */
@Local
public interface HardTokenSessionLocal extends HardTokenSession {

    /**
     * Returns all the X509Certificates datas mapped to the specified hard token.
     * 
     * @param tokensn The serialnumber of token.
     * @return a collection of X509Certificate datas
     */
    List<CertificateDataWrapper> getCertificateDatasFromHardToken(String tokensn);
}
