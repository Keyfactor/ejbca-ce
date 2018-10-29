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

/**
 * An ACME Authorization is the right to issue certificates for an identifier (e.g. a DNS Name).
 * 
 * @version $Id: AcmeAuthorization.java 29141 2018-06-07 12:52:44Z aminkh $
 */
public interface AcmeAuthorization {

    String getOrderId();

    void setOrderId(String orderId);

    String getAuthorizationId();

    void setAuthorizationId(String authorizationId);

    String getAccountId();

    void setAccountId(String accountId);

    AcmeIdentifier getAcmeIdentifier();

    void setAcmeIdentifier(AcmeIdentifier acmeIdentifier);

    long getExpires();

    void setExpires(long expires);

    boolean getWildcard();

    void setWildcard(boolean wildcard);

    AcmeAuthorizationStatus getStatus();

    void setStatus(AcmeAuthorizationStatus acmeAuthorizationStatus);

    float getLatestVersion();

    void upgrade();

    LinkedHashMap<Object, Object> getRawData();

}