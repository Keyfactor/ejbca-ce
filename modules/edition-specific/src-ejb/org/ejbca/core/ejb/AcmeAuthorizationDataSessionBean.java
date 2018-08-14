package org.ejbca.core.ejb;

import java.util.List;

import javax.ejb.Stateless;
import javax.ejb.TransactionAttribute;
import javax.ejb.TransactionAttributeType;

import org.cesecore.jndi.JndiConstants;
import org.ejbca.acme.AcmeAuthorizationData;
import org.ejbca.core.protocol.acme.AcmeAuthorization;
import org.ejbca.core.protocol.acme.AcmeAuthorizationDataSessionLocal;
import org.ejbca.core.protocol.acme.AcmeAuthorizationDataSessionRemote;

/**
 * Class that receives a Acme message and passes it on to the correct message handler.
 * Not available in Community Edition
 *
 * @version $Id: AcmeAuthorizationDataSessionBean.java 25797 2018-08-10 15:52:00Z jekaterina $
 */

@Stateless(mappedName = JndiConstants.APP_JNDI_PREFIX + "AcmeAuthorizationDataSessionRemote")
@TransactionAttribute(TransactionAttributeType.REQUIRED)
public class AcmeAuthorizationDataSessionBean implements AcmeAuthorizationDataSessionRemote, AcmeAuthorizationDataSessionLocal {

    @Override
    @TransactionAttribute(TransactionAttributeType.SUPPORTS)
    public AcmeAuthorization getAcmeAuthorization(String authorizationId) {
        throw new UnsupportedOperationException("ACME calls are only supported in EJBCA Enterprise");
    }

    @Override
    @TransactionAttribute(TransactionAttributeType.SUPPORTS)
    public List<AcmeAuthorization> getAcmeAuthorizationsByOrderIdId(String orderId) {
        throw new UnsupportedOperationException("ACME calls are only supported in EJBCA Enterprise");
    }

    @Override
    @TransactionAttribute(TransactionAttributeType.SUPPORTS)
    public AcmeAuthorizationData find(String authorizationId) {
        throw new UnsupportedOperationException("ACME calls are only supported in EJBCA Enterprise");
    }

    @Override
    @TransactionAttribute(TransactionAttributeType.SUPPORTS)
    public List<AcmeAuthorizationData> findByOrderId(String orderId) {
        throw new UnsupportedOperationException("ACME calls are only supported in EJBCA Enterprise");
    }

    @Override
    public String createOrUpdate(AcmeAuthorization acmeAuthorization) {
        throw new UnsupportedOperationException("ACME calls are only supported in EJBCA Enterprise");
    }

    @Override
    public void remove(String authorizationId) {
        throw new UnsupportedOperationException("ACME calls are only supported in EJBCA Enterprise");
    }
}
