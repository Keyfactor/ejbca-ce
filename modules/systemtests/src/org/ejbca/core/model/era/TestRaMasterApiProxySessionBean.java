/*************************************************************************
 *                                                                       *
 *  EJBCA: The OpenSource Certificate Authority                          *
 *                                                                       *
 *  This software is free software; you can redistribute it and/or       *
 *  modify it under the terms of the GNU Lesser General Public           *
 *  License as published by the Free Software Foundation; either         *
 *  version 2.1 of the License, or any later version.                    *
 *                                                                       *
 *  See terms of license at gnu.org.                                     *
 *                                                                       *
 *************************************************************************/
package org.ejbca.core.model.era;

import java.util.List;

import javax.ejb.EJB;
import javax.ejb.Stateless;
import javax.ejb.TransactionAttribute;
import javax.ejb.TransactionAttributeType;

import org.cesecore.authentication.AuthenticationFailedException;
import org.cesecore.authentication.tokens.AlwaysAllowLocalAuthenticationToken;
import org.cesecore.authentication.tokens.AuthenticationToken;
import org.cesecore.authorization.AuthorizationDeniedException;
import org.cesecore.certificates.ca.CADoesntExistsException;
import org.cesecore.certificates.endentity.EndEntityInformation;
import org.cesecore.jndi.JndiConstants;
import org.ejbca.core.EjbcaException;
import org.ejbca.core.model.approval.ApprovalException;
import org.ejbca.core.model.approval.WaitingForApprovalException;
import org.ejbca.core.model.ra.raadmin.EndEntityProfileValidationException;
import org.ejbca.core.protocol.NoSuchAliasException;
import org.ejbca.core.protocol.ssh.SshRequestMessage;
import org.ejbca.core.protocol.ws.objects.UserDataVOWS;

import com.keyfactor.util.certificate.CertificateWrapper;

/**
 * @version $Id$
 *
 */
@Stateless(mappedName = JndiConstants.APP_JNDI_PREFIX + "TestRaMasterApiProxySessionRemote")
@TransactionAttribute(TransactionAttributeType.SUPPORTS)
public class TestRaMasterApiProxySessionBean implements TestRaMasterApiProxySessionRemote {

    @EJB
    private RaMasterApiProxyBeanLocal raMasterApiProxyBean;

    @Override
    public void deferLocalForTest() {
        raMasterApiProxyBean.deferLocalForTest();
    }

    @Override
    public void enableFunctionTracingForTest() {
        raMasterApiProxyBean.enableFunctionTracingForTest();
    }

    @Override
    public List<String> getFunctionTraceForTest() {
        return raMasterApiProxyBean.getFunctionTraceForTest();
    }

    @Override
    public void restoreFunctionTracingAfterTest() {
        raMasterApiProxyBean.restoreFunctionTracingAfterTest();
    }

    @Override
    public byte[] cmpDispatch(byte[] pkiMessageBytes, String cmpConfigurationAlias)
            throws NoSuchAliasException {
        AuthenticationToken authenticationToken = new AlwaysAllowLocalAuthenticationToken("TestRaMasterApiProxySessionBean");
        return raMasterApiProxyBean.cmpDispatch(authenticationToken, pkiMessageBytes, cmpConfigurationAlias);
    }

    @Override
    public boolean isBackendAvailable(Class<? extends RaMasterApi> apiType) {
        return raMasterApiProxyBean.isBackendAvailable(apiType);
    }

    @Override
    public byte[] createCertificateWS(AuthenticationToken authenticationToken, UserDataVOWS userdata, String requestData, int requestType, String responseType)
            throws AuthorizationDeniedException, ApprovalException, EjbcaException, EndEntityProfileValidationException {
        return raMasterApiProxyBean.createCertificateWS(authenticationToken, userdata, requestData, requestType, null, responseType);
    }

    @Override
    public boolean addUser(AuthenticationToken authenticationToken, EndEntityInformation endEntity, boolean clearpwd)
            throws AuthorizationDeniedException, EjbcaException, WaitingForApprovalException {
        return raMasterApiProxyBean.addUser(authenticationToken, endEntity, clearpwd);
    }

    @Override
    public byte[] createCertificate(AuthenticationToken authenticationToken, EndEntityInformation endEntityInformation)
            throws AuthorizationDeniedException, EjbcaException {
        return raMasterApiProxyBean.createCertificate(authenticationToken, endEntityInformation);
    }

    @Override
    public byte[] enrollAndIssueSshCertificate(AuthenticationToken authenticationToken, EndEntityInformation endEntity,
            SshRequestMessage sshRequestMessage) throws AuthorizationDeniedException, EjbcaException, EndEntityProfileValidationException {
        return raMasterApiProxyBean.enrollAndIssueSshCertificate(authenticationToken, endEntity,
                sshRequestMessage);
    }
    
    @Override
    public RaCertificateSearchResponse searchForCertificates(AuthenticationToken authenticationToken,
            RaCertificateSearchRequest raCertificateSearchRequest) {
        return raMasterApiProxyBean.searchForCertificates(authenticationToken, raCertificateSearchRequest);
    }
    
    @Override
    public List<CertificateWrapper> searchForCertificateChainWithPreferredRoot(AuthenticationToken authenticationToken, 
            String fingerprint, String rootSubjectDnHash) {
        return raMasterApiProxyBean.searchForCertificateChainWithPreferredRoot(authenticationToken, fingerprint, rootSubjectDnHash);
    }
    
    @Override
    public RaAuthorizationResult getAuthorization(final AuthenticationToken authenticationToken) throws AuthenticationFailedException {
        return raMasterApiProxyBean.getAuthorization(authenticationToken);
    }
        
    @Override
    public byte[] keyRecoverEnrollWS(AuthenticationToken authenticationToken, String username, String certSNinHex, String issuerDN, String password, String hardTokenSN)
            throws AuthorizationDeniedException, CADoesntExistsException, EjbcaException, WaitingForApprovalException {
        return raMasterApiProxyBean.keyRecoverEnrollWS(authenticationToken, username, certSNinHex, issuerDN, password, hardTokenSN);
    }
    
}
