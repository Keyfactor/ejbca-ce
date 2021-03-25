package org.ejbca.core.ejb.ra;

import org.cesecore.authentication.tokens.AuthenticationToken;
import org.ejbca.core.ejb.ra.raadmin.AdminPreferenceSessionDefault;

import javax.ejb.Remote;

/*
Remote interface to allow access to local methods from system tests
 */
@Remote
public interface AdminPreferenceProxySessionRemote extends AdminPreferenceSessionDefault {

    /**
     * Deletes the admin preference belonging to the given administrator.
     *  @param token Authentication token of the administrator
     */
    void deleteAdminPreferences(final AuthenticationToken token);

}
