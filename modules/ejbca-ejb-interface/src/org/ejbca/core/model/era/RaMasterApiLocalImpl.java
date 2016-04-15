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
package org.ejbca.core.model.era;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.List;

import org.apache.log4j.Logger;
import org.cesecore.authentication.AuthenticationFailedException;
import org.cesecore.authentication.tokens.AuthenticationToken;
import org.cesecore.authorization.AuthorizationDeniedException;
import org.cesecore.authorization.access.AccessSet;
import org.cesecore.authorization.control.AccessControlSessionLocal;
import org.cesecore.certificates.ca.CAConstants;
import org.cesecore.certificates.ca.CADoesntExistsException;
import org.cesecore.certificates.ca.CAInfo;
import org.cesecore.certificates.ca.CaSessionLocal;
import org.cesecore.certificates.certificate.CertificateDataWrapper;
import org.cesecore.certificates.certificate.CertificateStoreSessionLocal;
import org.cesecore.certificates.endentity.EndEntityInformation;
import org.ejbca.core.EjbcaException;
import org.ejbca.core.ejb.ra.EndEntityAccessSessionLocal;
import org.ejbca.core.model.util.EjbLocalHelper;

/**
 * Implementation of the RaMasterApi that invokes functions at the local node.
 * 
 * @version $Id$
 */
public class RaMasterApiLocalImpl implements RaMasterApi {
    
    private static final Logger log = Logger.getLogger(RaMasterApiLocalImpl.class);

    private final AccessControlSessionLocal accessControlSession;
    private final CaSessionLocal caSession;
    private final CertificateStoreSessionLocal certificateStoreSession;
    private final EndEntityAccessSessionLocal endEntityAccessSession;
    private Boolean backendAvailable = null;
    
    public RaMasterApiLocalImpl() {
        final EjbLocalHelper ejb = new EjbLocalHelper();
        accessControlSession = ejb.getAccessControlSession();
        caSession = ejb.getCaSession();
        certificateStoreSession = ejb.getCertificateStoreSession();
        endEntityAccessSession = ejb.getEndEntityAccessSession();
    }

    @Override
    public boolean isBackendAvailable() {
        if (backendAvailable==null) {
            boolean available = false;
            for (int caId : caSession.getAllCaIds()) {
                try {
                    if (caSession.getCAInfoInternal(caId).getStatus() == CAConstants.CA_ACTIVE) {
                        available = true;
                        break;
                    }
                } catch (CADoesntExistsException e) {
                    log.debug("Fail to get existing CA's info. " + e.getMessage());
                }
            }
            backendAvailable = Boolean.valueOf(available);
        }
        return backendAvailable.booleanValue();
    }
    
    @Override
    public AccessSet getUserAccessSet(final AuthenticationToken authenticationToken) throws AuthenticationFailedException  {
        return accessControlSession.getAccessSetForAuthToken(authenticationToken);
    }
    
    @Override
    public List<AccessSet> getUserAccessSets(final List<AuthenticationToken> authenticationTokens)  {
        final List<AccessSet> ret = new ArrayList<>();
        for (AuthenticationToken authToken : authenticationTokens) {
            // Always add, even if null. Otherwise the caller won't be able to determine which AccessSet belongs to which AuthenticationToken
            AccessSet as;
            try {
                as = accessControlSession.getAccessSetForAuthToken(authToken);
            } catch (AuthenticationFailedException e) {
                as = null;
            }
            ret.add(as);
        }
        return ret;
    }

    @Override
    public List<CAInfo> getAuthorizedCas(AuthenticationToken authenticationToken) {
        return caSession.getAuthorizedAndNonExternalCaInfos(authenticationToken);
    }

    @Override
    public CertificateDataWrapper searchForCertificate(final AuthenticationToken authenticationToken, final String fingerprint) {
        final CertificateDataWrapper cdw = certificateStoreSession.getCertificateData(fingerprint);
        if (cdw==null) {
            return null;
        }
        if (!caSession.authorizedToCANoLogging(authenticationToken, cdw.getCertificateData().getIssuerDN().hashCode())) {
            return null;
        }
        // TODO: Check EEP authorization once this is implemented
        return cdw;
    }

    @Override
    public List<CertificateDataWrapper> searchForCertificates(AuthenticationToken authenticationToken, List<Integer> caIds) {
        final List<Integer> authorizedLocalCaIds = new ArrayList<>(caSession.getAuthorizedCaIds(authenticationToken));
        authorizedLocalCaIds.retainAll(caIds);
        List<CertificateDataWrapper> ret = new ArrayList<>();
        // TODO: Proper critera builder with sanity checking and result object that be used for additional paginated requests
        for (final int caId : authorizedLocalCaIds) {
            try {
                final Collection<String> fingerprints = certificateStoreSession.listAllCertificates(caSession.getCAInfoInternal(caId).getSubjectDN());
                for (final String fingerprint : fingerprints) {
                    ret.add(certificateStoreSession.getCertificateData(fingerprint));
                    if (ret.size()>1000) {
                        log.info("DEVELOP Temporary search algorithm returned more the hard coded limit of entries.");
                        return ret;
                    }
                }
            } catch (CADoesntExistsException e) {
                log.warn("CA went missing during search operation. " + e.getMessage());
            }
        }
        return ret;
    }

    @Override
    public String testCall(AuthenticationToken authenticationToken, String argument1, int argument2) throws AuthorizationDeniedException, EjbcaException {
        // Simple example to prove that invocation of EJB works
        if (endEntityAccessSession!=null) {
            final EndEntityInformation eei = endEntityAccessSession.findUser("superadmin");
            if (eei!=null) {
                return eei.getDN();
            }
        }
        return "unknown (local call)";
    }

    @Override
    public String testCallPreferLocal(AuthenticationToken authenticationToken, String requestData) throws AuthorizationDeniedException {
        return "RaMasterApiLocalImpl.testCallPreferLocal";
    }

    @Override
    public List<String> testCallMerge(AuthenticationToken authenticationToken, String requestData) throws AuthorizationDeniedException {
        return Arrays.asList(new String[] {"RaMasterApiLocalImpl.testCallMerge"});
    }

    @Override
    public String testCallPreferCache(AuthenticationToken authenticationToken, String requestData) throws AuthorizationDeniedException {
        throw new UnsupportedOperationException();
    }
}
