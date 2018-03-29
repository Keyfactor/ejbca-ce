package org.ejbca.core.ejb.unidfnr;

import javax.ejb.Stateless;
import javax.ejb.TransactionAttribute;
import javax.ejb.TransactionAttributeType;

import org.cesecore.jndi.JndiConstants;
import org.ejbca.core.model.util.EjbLocalHelper;

@Stateless(mappedName = JndiConstants.APP_JNDI_PREFIX + "UnidfnrSessionProxyRemote")
@TransactionAttribute(TransactionAttributeType.SUPPORTS)
public class UnidfnrProxySessionBean implements UnidfnrProxySessionRemote {

    private UnidfnrSessionLocal unidfnrSession = new EjbLocalHelper().getUnidfnrSession();

    public void removeUnidFnrDataIfPresent(final String unid) {
        unidfnrSession.removeUnidFnrDataIfPresent(unid);
    }

    public void stroreUnidFnrData(final String unid, final String fnr) {
        unidfnrSession.stroreUnidFnrData(unid, fnr);
    }
}
