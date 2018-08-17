package org.ejbca.core.protocol.acme;

import java.util.List;

import javax.ejb.Local;

import org.ejbca.acme.AcmeAuthorizationData;

/**
 * Local interface for AcmeAuthorizationDataSessionLocal
 *
 * @version $Id: AcmeAuthorizationDataSessionLocal.java 25797 2018-08-10 15:52:00Z jekaterina $
 */
@Local
public interface AcmeAuthorizationDataSessionLocal extends AcmeAuthorizationDataSession {


    /**
     * @param authorizationId the authorization ID of an AcmeAuthorizationData row
     * @return the sought object, or null if not found
     */
    AcmeAuthorizationData find(final String authorizationId);

    /**
     *
     * @param orderId the order ID
     * @return the list of sought objects, or null if not found
     */
    List<AcmeAuthorizationData> findByOrderId(final String orderId);

    /**
     *
     * @param accountId the account ID
     * @return the list of sought objects, or null if not found
     */
    List<AcmeAuthorizationData> findByAccountId(final String accountId);

    /**
     * Create or update the AcmeAuthorization.
     *
     * @return the id of persisted version of the AcmeAuthorization.
     */
    String createOrUpdate(final AcmeAuthorization acmeAuthorization);


    /**
     * Create or update the AcmeAuthorizations .
     */
    void createOrUpdateList(final List<AcmeAuthorization> acmeAuthorizations);

    /**
     * Removes an ACME authorization with the given ID. Fails silently if no such ACME Authorization exists.
     *
     * @param authorizationId the ACME authorization ID
     */
    void remove(final String authorizationId);

}
