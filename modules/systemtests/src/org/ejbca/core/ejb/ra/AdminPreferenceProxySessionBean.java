package org.ejbca.core.ejb.ra;

import org.cesecore.authentication.tokens.AuthenticationToken;
import org.cesecore.config.CesecoreConfiguration;
import org.ejbca.core.ejb.ra.raadmin.AdminPreferenceSessionDefault;

import jakarta.ejb.EJB;
import jakarta.ejb.Stateless;
import jakarta.ejb.TransactionAttribute;
import jakarta.ejb.TransactionAttributeType;
import jakarta.persistence.EntityManager;
import jakarta.persistence.PersistenceContext;
import jakarta.persistence.Query;

@Stateless
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
