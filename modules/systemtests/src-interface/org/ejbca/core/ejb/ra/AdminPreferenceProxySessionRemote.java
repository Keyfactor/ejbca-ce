package org.ejbca.core.ejb.ra;

import javax.ejb.Remote;

import org.cesecore.authentication.tokens.AuthenticationToken;

/*
Remote interface to allow access to local methods from system tests
 */
@Remote
public interface AdminPreferenceProxySessionRemote {

    /**
     * Deletes the admin preference belonging to the given administrator.
     *  @param token Authentication token of the administrator
     */
    void deleteAdminPreferences(final AuthenticationToken token);

}
