package org.ejbca.core.ejb.unidfnr;

import javax.ejb.Stateless;
import javax.ejb.TransactionAttribute;
import javax.ejb.TransactionAttributeType;
import javax.inject.Inject;

import org.cesecore.jndi.JndiConstants;

@Stateless(mappedName = JndiConstants.APP_JNDI_PREFIX + "UnidfnrSessionProxyRemote")
@TransactionAttribute(TransactionAttributeType.SUPPORTS)
public class UnidfnrProxySessionBean implements UnidfnrProxySessionRemote {

    @Inject
    private UnidfnrSessionLocal unidfnrSession;

    public void removeUnidFnrDataIfPresent(final String unid) {
        unidfnrSession.removeUnidFnrDataIfPresent(unid);
    }

    public void stroreUnidFnrData(final String unid, final String fnr) {
        unidfnrSession.stroreUnidFnrData(unid, fnr);
    }
}
