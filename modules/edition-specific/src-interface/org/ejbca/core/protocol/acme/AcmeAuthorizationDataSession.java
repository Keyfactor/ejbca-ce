package org.ejbca.core.protocol.acme;

import java.util.List;

/**
 * @version $Id: AcmeAuthorizationDataSession.java 25797 2018-08-10 15:52:00Z jekaterina $
 */
public interface AcmeAuthorizationDataSession {
    static final String ACME_MODULE = "acme";


    /**
     *
     * @param authorizationId the ID of the authorization
     * @return the sought authorization, or null if none exists
     */
    AcmeAuthorization getAcmeAuthorization(final String authorizationId);

    /**
     *
     * @param orderId the ID of the order
     * @return list of sought authorizations, or empty list if none exists
     */
    List<AcmeAuthorization> getAcmeAuthorizationsByOrderIdId(final String orderId);

}
