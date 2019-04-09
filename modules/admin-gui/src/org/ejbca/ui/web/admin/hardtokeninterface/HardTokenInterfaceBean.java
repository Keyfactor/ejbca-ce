/*************************************************************************
 *                                                                       *
 *  EJBCA Community: The OpenSource Certificate Authority                *
 *                                                                       *
 *  This software is free software; you can redistribute it and/or       *
 *  modify it under the terms of the GNU Lesser General Public           *
 *  License as published by the Free Software Foundation; either         *
 *  version 2.1 of the License, or any later version.                    *
 *                                                                       *
 *  See terms of license at gnu.org.                                     *
 *                                                                       *
 *************************************************************************/

package org.ejbca.ui.web.admin.hardtokeninterface;

import java.io.Serializable;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.util.Collection;
import java.util.HashMap;
import java.util.Iterator;
import java.util.List;
import java.util.Map;

import javax.servlet.http.HttpServletRequest;

import org.cesecore.authentication.tokens.AuthenticationToken;
import org.cesecore.authorization.AuthorizationDeniedException;
import org.cesecore.roles.Role;
import org.cesecore.roles.management.RoleSessionLocal;
import org.cesecore.util.EJBTools;
import org.ejbca.core.ejb.hardtoken.HardTokenBatchJobSession;
import org.ejbca.core.ejb.hardtoken.HardTokenSession;
import org.ejbca.core.ejb.keyrecovery.KeyRecoverySession;
import org.ejbca.core.model.authorization.AccessRulesConstants;
import org.ejbca.core.model.hardtoken.HardTokenInformation;
import org.ejbca.core.model.hardtoken.HardTokenIssuer;
import org.ejbca.core.model.hardtoken.HardTokenIssuerDoesntExistsException;
import org.ejbca.core.model.hardtoken.HardTokenIssuerExistsException;
import org.ejbca.core.model.hardtoken.HardTokenIssuerInformation;
import org.ejbca.core.model.util.EjbLocalHelper;
import org.ejbca.ui.web.admin.rainterface.RAInterfaceBean;
import org.ejbca.ui.web.jsf.configuration.EjbcaWebBean;

/**
 * A java bean handling the interface between EJBCA hard token module and JSP pages.
 * <p>
 * Semi-deprecated since EJBCA 7.0.0. Try to use session beans directly from managed beans (GUI), rather than this extra layer.
 * 
 * @version $Id$
 */
public class HardTokenInterfaceBean implements Serializable {

    private static final long serialVersionUID = -3930279705572942527L;
    private HardTokenSession hardtokensession;
    private KeyRecoverySession keyrecoverysession;
    private HardTokenBatchJobSession hardtokenbatchsession;
    private RoleSessionLocal roleSession;
    private AuthenticationToken admin;
    private boolean initialized = false;
    private HardTokenView[] result;

    /** Creates new LogInterfaceBean */
    public HardTokenInterfaceBean() {
    }

    /**
     * Method that initialized the bean.
     *
     * @param request is a reference to the http request.
     */
    public void initialize(HttpServletRequest request, EjbcaWebBean ejbcawebbean) throws Exception {
        if (!initialized) {
            admin = ejbcawebbean.getAdminObject();
            EjbLocalHelper ejbLocalHelper = new EjbLocalHelper();
            hardtokensession = ejbLocalHelper.getHardTokenSession();
            hardtokenbatchsession = ejbLocalHelper.getHardTokenBatchJobSession();
            keyrecoverysession = ejbLocalHelper.getKeyRecoverySession();
            roleSession = new EjbLocalHelper().getRoleSession();
            initialized = true;
        }
    }

    /** Returns the first found hard token for the given username. */
    public HardTokenView getHardTokenViewWithUsername(String username, boolean includePUK) {
        this.result = null;
        Collection<HardTokenInformation> res = hardtokensession.getHardTokens(admin, username, includePUK);
        Iterator<HardTokenInformation> iter = res.iterator();
        if (res.size() > 0) {
            this.result = new HardTokenView[res.size()];
            for (int i = 0; iter.hasNext(); i++) {
                this.result[i] = new HardTokenView(iter.next());
            }
            if (this.result != null && this.result.length > 0) {
                return this.result[0];
            }
        }
        return null;
    }

    public HardTokenView getHardTokenViewWithIndex(String username, int index, boolean includePUK) {
        HardTokenView returnval = null;
        if (result == null) {
            getHardTokenViewWithUsername(username, includePUK);
        }
        if (result != null) {
            if (index < result.length) {
                returnval = result[index];
            }
        }
        return returnval;
    }

    public int getHardTokensInCache() {
        int returnval = 0;
        if (result != null) {
            returnval = result.length;
        }
        return returnval;
    }

    public HardTokenView getHardTokenView(String tokensn, boolean includePUK) throws AuthorizationDeniedException {
        HardTokenView returnval = null;
        this.result = null;
        HardTokenInformation token = hardtokensession.getHardToken(admin, tokensn, includePUK);
        if (token != null) {
            returnval = new HardTokenView(token);
        }
        return returnval;
    }

    public String[] getHardTokenIssuerAliases() {
        return hardtokensession.getHardTokenIssuers(admin).keySet().toArray(new String[0]);
    }

    /** Returns the alias from id. */
    public String getHardTokenIssuerAlias(int id) {
        return hardtokensession.getHardTokenIssuerAlias(id);
    }

    public int getHardTokenIssuerId(String alias) {
        return hardtokensession.getHardTokenIssuerId(alias);
    }

    public HardTokenIssuerInformation getHardTokenIssuerInformation(String alias) {
        return hardtokensession.getHardTokenIssuerInformation(alias);
    }

    public HardTokenIssuerInformation getHardTokenIssuerInformation(int id) {
        return hardtokensession.getHardTokenIssuerInformation(id);
    }
    
    public Map<Integer, String> getRoleIdToNameMap() {
        final HashMap<Integer, String> roleIdToNameMap = new HashMap<>();
        for (final Role role : roleSession.getAuthorizedRoles(admin)) {
            roleIdToNameMap.put(role.getRoleId(), role.getRoleNameFull());
        }
        return roleIdToNameMap;
    }
    
    public List<Role> getHardTokenIssuingRoles() {
        return roleSession.getAuthorizedRolesWithAccessToResource(admin, AccessRulesConstants.HARDTOKEN_ISSUEHARDTOKENS);
    }

    public void addHardTokenIssuer(String alias, int roleId) throws HardTokenIssuerExistsException, AuthorizationDeniedException {
        for (final Role role : getHardTokenIssuingRoles()) {
            if (role.getRoleId()==roleId) {
                if (!hardtokensession.addHardTokenIssuer(admin, alias, roleId, new HardTokenIssuer())) {
                    throw new HardTokenIssuerExistsException();
                }
            }
        }
    }

    public void changeHardTokenIssuer(String alias, HardTokenIssuer hardtokenissuer) throws HardTokenIssuerDoesntExistsException,
            AuthorizationDeniedException {
        if (hardtokensession.isAuthorizedToEditHardTokenIssuer(admin, alias)) {
            if (!hardtokensession.changeHardTokenIssuer(admin, alias, hardtokenissuer)) {
                throw new HardTokenIssuerDoesntExistsException();
            }
        }
    }

    /** Returns false if profile is used by any user or in authorization rules. 
     * @throws AuthorizationDeniedException */
    public boolean removeHardTokenIssuer(String alias) throws AuthorizationDeniedException {
        boolean issuerused = false;
        if (hardtokensession.isAuthorizedToEditHardTokenIssuer(admin, alias)) {
            int issuerid = hardtokensession.getHardTokenIssuerId(alias);
            // Check if any users or authorization rule use the profile.
            issuerused = hardtokenbatchsession.checkForHardTokenIssuerId(issuerid);
            if (!issuerused) {
                hardtokensession.removeHardTokenIssuer(admin, alias);
            }
        }
        return !issuerused;
    }

    public void renameHardTokenIssuer(String oldalias, String newalias, int newRoleId) throws HardTokenIssuerExistsException,
            AuthorizationDeniedException {
        if (hardtokensession.isAuthorizedToEditHardTokenIssuer(admin, oldalias)) {
            if (!hardtokensession.renameHardTokenIssuer(admin, oldalias, newalias, newRoleId)) {
                throw new HardTokenIssuerExistsException();
            }
        }
    }

    public void cloneHardTokenIssuer(String oldalias, String newalias, int newRoleId) throws HardTokenIssuerExistsException,
            AuthorizationDeniedException {
        if (hardtokensession.isAuthorizedToEditHardTokenIssuer(admin, oldalias)) {
            if (!hardtokensession.cloneHardTokenIssuer(admin, oldalias, newalias, newRoleId)) {
                throw new HardTokenIssuerExistsException();
            }
        }
    }

    /**
     * Method that checks if a token is key recoverable and also check if the administrator is authorized to the action.
     */
    public boolean isTokenKeyRecoverable(String tokensn, String username, RAInterfaceBean rabean) throws Exception {
        boolean retval = false;
        X509Certificate keyRecCert = null;
        for (final Certificate cert : hardtokensession.findCertificatesInHardToken(tokensn)) {
            final X509Certificate x509cert = (X509Certificate) cert;
            if (keyrecoverysession.existsKeys(EJBTools.wrap(x509cert))) {
                keyRecCert = x509cert;
            }
        }
        if (keyRecCert != null) {
            retval = rabean.keyRecoveryPossible(keyRecCert, username);
        }
        return retval;
    }

    public void markTokenForKeyRecovery(String tokensn, String username, RAInterfaceBean rabean) throws Exception {
        for (final Certificate cert : hardtokensession.findCertificatesInHardToken(tokensn)) {
            final X509Certificate x509cert = (X509Certificate) cert;
            if (keyrecoverysession.existsKeys(EJBTools.wrap(x509cert))) {
                rabean.markForRecovery(username, x509cert);
            }
        }
    }
}
