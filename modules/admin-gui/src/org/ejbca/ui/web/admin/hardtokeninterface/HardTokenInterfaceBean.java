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
import java.util.Iterator;

import javax.servlet.http.HttpServletRequest;

import org.cesecore.authentication.tokens.AuthenticationToken;
import org.cesecore.authorization.AuthorizationDeniedException;
import org.cesecore.authorization.control.AccessControlSessionLocal;
import org.cesecore.certificates.ca.CaSessionLocal;
import org.cesecore.certificates.certificateprofile.CertificateProfileSession;
import org.cesecore.roles.RoleData;
import org.ejbca.core.ejb.hardtoken.HardTokenBatchJobSession;
import org.ejbca.core.ejb.hardtoken.HardTokenSession;
import org.ejbca.core.ejb.keyrecovery.KeyRecoverySession;
import org.ejbca.core.ejb.ra.EndEntityManagementSessionLocal;
import org.ejbca.core.model.hardtoken.HardTokenInformation;
import org.ejbca.core.model.hardtoken.HardTokenIssuer;
import org.ejbca.core.model.hardtoken.HardTokenIssuerInformation;
import org.ejbca.core.model.hardtoken.HardTokenIssuerDoesntExistsException;
import org.ejbca.core.model.hardtoken.HardTokenIssuerExistsException;
import org.ejbca.core.model.util.EjbLocalHelper;
import org.ejbca.ui.web.admin.configuration.EjbcaWebBean;
import org.ejbca.ui.web.admin.configuration.InformationMemory;
import org.ejbca.ui.web.admin.rainterface.RAInterfaceBean;

/**
 * A java bean handling the interface between EJBCA hard token module and JSP pages.
 *
 * @version $Id$
 */
public class HardTokenInterfaceBean implements Serializable {

    private static final long serialVersionUID = -3930279705572942527L;
    private HardTokenSession hardtokensession;
    private KeyRecoverySession keyrecoverysession;
    private HardTokenBatchJobSession hardtokenbatchsession;
    private AuthenticationToken admin;
    private InformationMemory informationmemory;
    private boolean initialized = false;
    private HardTokenView[] result;
    private HardTokenProfileDataHandler hardtokenprofiledatahandler;

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
            AccessControlSessionLocal authorizationsession = ejbLocalHelper.getAccessControlSession();
            EndEntityManagementSessionLocal endEntityManagementSession = ejbLocalHelper.getEndEntityManagementSession();
            CertificateProfileSession certificateProfileSession = ejbLocalHelper.getCertificateProfileSession();
            keyrecoverysession = ejbLocalHelper.getKeyRecoverySession();
            CaSessionLocal caSession = ejbLocalHelper.getCaSession();
            initialized = true;
            this.informationmemory = ejbcawebbean.getInformationMemory();
            this.hardtokenprofiledatahandler = new HardTokenProfileDataHandler(admin, hardtokensession, certificateProfileSession,
                    authorizationsession, endEntityManagementSession, caSession, informationmemory);
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
        return (String[]) hardtokensession.getHardTokenIssuers(admin).keySet().toArray(new String[0]);
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

    public void addHardTokenIssuer(String alias, int roleId) throws HardTokenIssuerExistsException, AuthorizationDeniedException {
        Iterator<RoleData> iter = this.informationmemory.getHardTokenIssuingRoles().iterator();
        while (iter.hasNext()) {
            if (iter.next().getPrimaryKey() == roleId) {
                if (!hardtokensession.addHardTokenIssuer(admin, alias, roleId, new HardTokenIssuer())) {
                    throw new HardTokenIssuerExistsException();
                }
                informationmemory.hardTokenDataEdited();
            }
        }
    }

    public void changeHardTokenIssuer(String alias, HardTokenIssuer hardtokenissuer) throws HardTokenIssuerDoesntExistsException,
            AuthorizationDeniedException {
        if (hardtokensession.isAuthorizedToEditHardTokenIssuer(admin, alias)) {
            if (!hardtokensession.changeHardTokenIssuer(admin, alias, hardtokenissuer)) {
                throw new HardTokenIssuerDoesntExistsException();
            }
            informationmemory.hardTokenDataEdited();
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
                informationmemory.hardTokenDataEdited();
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
            informationmemory.hardTokenDataEdited();
        }
    }

    public void cloneHardTokenIssuer(String oldalias, String newalias, int newRoleId) throws HardTokenIssuerExistsException,
            AuthorizationDeniedException {
        if (hardtokensession.isAuthorizedToEditHardTokenIssuer(admin, oldalias)) {
            if (!hardtokensession.cloneHardTokenIssuer(admin, oldalias, newalias, newRoleId)) {
                throw new HardTokenIssuerExistsException();
            }
            informationmemory.hardTokenDataEdited();
        }
    }

    /**
     * Method that checks if a token is key recoverable and also check if the administrator is authorized to the action.
     */
    public boolean isTokenKeyRecoverable(String tokensn, String username, RAInterfaceBean rabean) throws Exception {
        boolean retval = false;
        X509Certificate keyRecCert = null;
        Iterator<Certificate> iter = hardtokensession.findCertificatesInHardToken(tokensn).iterator();
        while (iter.hasNext()) {
            X509Certificate cert = (X509Certificate) iter.next();
            if (keyrecoverysession.existsKeys(cert)) {
                keyRecCert = cert;
            }
        }
        if (keyRecCert != null) {
            retval = rabean.keyRecoveryPossible(keyRecCert, username);
        }
        return retval;
    }

    public void markTokenForKeyRecovery(String tokensn, String username, RAInterfaceBean rabean) throws Exception {
        Iterator<Certificate> iter = hardtokensession.findCertificatesInHardToken(tokensn).iterator();
        while (iter.hasNext()) {
            X509Certificate cert = (X509Certificate) iter.next();
            if (keyrecoverysession.existsKeys(cert)) {
                rabean.markForRecovery(username, cert);
            }
        }
    }

    public HardTokenProfileDataHandler getHardTokenProfileDataHandler() {
        return hardtokenprofiledatahandler;
    }
}
