package org.ejbca.core.ejb.ra;

import org.cesecore.authentication.tokens.AuthenticationToken;
import org.cesecore.config.CesecoreConfiguration;
import org.cesecore.jndi.JndiConstants;
import org.ejbca.core.ejb.ra.raadmin.AdminPreferenceSessionDefault;

import javax.ejb.EJB;
import javax.ejb.Stateless;
import javax.ejb.TransactionAttribute;
import javax.ejb.TransactionAttributeType;
import javax.persistence.EntityManager;
import javax.persistence.PersistenceContext;
import javax.persistence.Query;

@Stateless(mappedName = JndiConstants.APP_JNDI_PREFIX + "AdminPreferenceProxySessionRemote")
@TransactionAttribute(TransactionAttributeType.REQUIRED)
public class AdminPreferenceProxySessionBean extends AdminPreferenceSessionDefault implements AdminPreferenceProxySessionRemote {
    @EJB
    private EndEntityManagementSessionLocal endEntityManagementSession;

    @PersistenceContext(unitName = CesecoreConfiguration.PERSISTENCE_UNIT)
    private EntityManager entityManager;
    @Override
    public void deleteAdminPreferences(AuthenticationToken token) {
        final String id = makeAdminPreferenceId(token);
        Query query = entityManager.createQuery("DELETE FROM AdminPreferencesData ap WHERE ap.id=:id ");
        query.setParameter("id", id);
        query.executeUpdate();
    }

}
