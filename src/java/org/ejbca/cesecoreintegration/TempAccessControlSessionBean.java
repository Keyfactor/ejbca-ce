package org.ejbca.cesecoreintegration;

import javax.ejb.Stateless;
import javax.ejb.TransactionAttribute;
import javax.ejb.TransactionAttributeType;

import org.cesecore.authentication.tokens.AuthenticationToken;
import org.cesecore.authorization.control.AccessControlSessionLocal;
import org.cesecore.authorization.control.AccessControlSessionRemote;
import org.cesecore.jndi.JndiConstants;

/**
 * Temporary class used during integration of CESeCore. REPLACE WITH REAL IMPL!
 * 
 * @version $Id$
 */
@Stateless(mappedName = JndiConstants.APP_JNDI_PREFIX + "AccessControlSessionRemote")
@TransactionAttribute(TransactionAttributeType.REQUIRED)
public class TempAccessControlSessionBean implements AccessControlSessionLocal, AccessControlSessionRemote {

	@Override
	public void forceCacheExpire() {
	}

	@Override
	public boolean isAuthorized(final AuthenticationToken authenticationToken, final String resource) {
		return true;
	}

}
