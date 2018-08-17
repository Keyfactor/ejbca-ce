package org.ejbca.core.protocool.acme;

import javax.ejb.EJB;
import javax.ejb.Stateless;
import javax.ejb.TransactionAttribute;
import javax.ejb.TransactionAttributeType;

import org.cesecore.jndi.JndiConstants;
import org.ejbca.core.protocol.acme.AcmeAuthorization;
import org.ejbca.core.protocol.acme.AcmeAuthorizationDataSessionLocal;
import org.ejbca.core.protocol.acme.AcmeAuthorizationDataSessionProxyRemote;

/**
 * @version $Id: AcmeAuthorizationDataSessionProxyBean.java 25797 2018-08-10 15:52:00Z jekaterina $
 *
 */
@Stateless(mappedName = JndiConstants.APP_JNDI_PREFIX + "AcmeAuthorizationDataSessionProxyRemote")
@TransactionAttribute(TransactionAttributeType.SUPPORTS)
public class AcmeAuthorizationDataSessionProxyBean implements AcmeAuthorizationDataSessionProxyRemote {

    @EJB
    private AcmeAuthorizationDataSessionLocal acmeAuthorizationDataSessionLocal;

    @Override
    public String createOrUpdate(AcmeAuthorization acmeAuthorization) {
        return acmeAuthorizationDataSessionLocal.createOrUpdate(acmeAuthorization);
    }

    @Override
    public void remove(String authorizationId) {
        acmeAuthorizationDataSessionLocal.remove(authorizationId);
    }
}
