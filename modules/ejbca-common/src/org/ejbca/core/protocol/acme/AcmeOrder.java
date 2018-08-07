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
package org.ejbca.core.protocol.acme;

import java.util.LinkedHashMap;
import java.util.List;

import org.cesecore.certificates.endentity.EndEntityInformation;
import org.ejbca.core.protocol.acme.response.AcmeProblemResponse;

/**
 * ACME Order object
 * 
 * @version $Id$
 */
public interface AcmeOrder {

    String getOrderId();

    String getAccountId();

    String getFinalize();

    void setFinalize(String finalize);

    List<AcmeIdentifier> getIdentifiers();

    void setIdentifiers(List<AcmeIdentifier> identifiers);

    long getNotBefore();

    long getNotAfter();

    long getExpires();

    AcmeOrderStatus getAcmeOrderStatus();

    void setAcmeOrderStatus(AcmeOrderStatus acmeOrderStatus);

    String getCertificateId();

    void setCertificateId(String certificateId);

    List<String> getAuthorizationIds();

    void setAuthorizationIds(List<String> authorizationIds);

    AcmeProblemResponse getError();

    void setError(AcmeProblemResponse acmeProblemResponse);

    void setEndEntityInformation(EndEntityInformation endEntityInformation);

    EndEntityInformation getEndEntityInformation();

    float getLatestVersion();

    void upgrade();
    
    LinkedHashMap<Object, Object> getRawData();

}