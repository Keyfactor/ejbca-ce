package org.ejbca.core.protocool.acme;

import javax.ejb.EJB;
import javax.ejb.Stateless;
import javax.ejb.TransactionAttribute;
import javax.ejb.TransactionAttributeType;

import org.cesecore.jndi.JndiConstants;
import org.ejbca.core.protocol.acme.AcmeChallenge;
import org.ejbca.core.protocol.acme.AcmeChallengeDataSessionLocal;
import org.ejbca.core.protocol.acme.AcmeChallengeDataSessionProxyRemote;

/**
 * @version $Id: AcmeChallengeDataSessionProxyBean.java 25797 2018-08-10 15:52:00Z jekaterina $
 */
@Stateless(mappedName = JndiConstants.APP_JNDI_PREFIX + "AcmeChallengeDataSessionProxyRemote")
@TransactionAttribute(TransactionAttributeType.SUPPORTS)
public class AcmeChallengeDataSessionProxyBean implements AcmeChallengeDataSessionProxyRemote {


    @EJB
    private AcmeChallengeDataSessionLocal acmeChallengeDataSession;

    @Override
    public String createOrUpdate(AcmeChallenge acmeChallenge) {
        return acmeChallengeDataSession.createOrUpdate(acmeChallenge);
    }

    @Override
    public void remove(String challengeId) {
        acmeChallengeDataSession.remove(challengeId);
    }
}
