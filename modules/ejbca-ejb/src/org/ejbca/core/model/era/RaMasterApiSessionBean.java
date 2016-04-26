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
import java.util.Collections;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

import javax.ejb.EJB;
import javax.ejb.Stateless;
import javax.ejb.TransactionAttribute;
import javax.ejb.TransactionAttributeType;
import javax.persistence.EntityManager;
import javax.persistence.PersistenceContext;
import javax.persistence.Query;

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
import org.cesecore.certificates.certificate.CertificateConstants;
import org.cesecore.certificates.certificate.CertificateDataWrapper;
import org.cesecore.certificates.certificate.CertificateStoreSessionLocal;
import org.cesecore.certificates.certificateprofile.CertificateProfile;
import org.cesecore.certificates.certificateprofile.CertificateProfileSessionLocal;
import org.cesecore.certificates.endentity.EndEntityInformation;
import org.cesecore.config.CesecoreConfiguration;
import org.cesecore.util.CertTools;
import org.cesecore.util.StringTools;
import org.ejbca.core.EjbcaException;
import org.ejbca.core.ejb.ra.EndEntityAccessSessionLocal;
import org.ejbca.core.ejb.ra.raadmin.EndEntityProfileSessionLocal;
import org.ejbca.core.model.authorization.AccessRulesConstants;
import org.ejbca.core.model.ra.raadmin.EndEntityProfile;

/**
 * Implementation of the RaMasterApi that invokes functions at the local node.
 * 
 * @version $Id$
 */
@Stateless//(mappedName = JndiConstants.APP_JNDI_PREFIX + "RaMasterApiSessionRemote")
@TransactionAttribute(TransactionAttributeType.NOT_SUPPORTED)
public class RaMasterApiSessionBean implements RaMasterApiSessionLocal {
    
    private static final Logger log = Logger.getLogger(RaMasterApiSessionBean.class);

    @EJB
    private AccessControlSessionLocal accessControlSession;
    @EJB
    private CaSessionLocal caSession;
    @EJB
    private CertificateStoreSessionLocal certificateStoreSession;
    @EJB
    private EndEntityAccessSessionLocal endEntityAccessSession;
    @EJB
    private EndEntityProfileSessionLocal endEntityProfileSession;
    @EJB
    private CertificateProfileSessionLocal certificateProfileSession;

    @PersistenceContext(unitName = CesecoreConfiguration.PERSISTENCE_UNIT)
    private EntityManager entityManager;

    @Override
    public boolean isBackendAvailable() {
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
        return available;
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
    public RaCertificateSearchResponse searchForCertificates(AuthenticationToken authenticationToken, RaCertificateSearchRequest request) {
        final RaCertificateSearchResponse response = new RaCertificateSearchResponse();
        final List<Integer> authorizedLocalCaIds = new ArrayList<>(caSession.getAuthorizedCaIds(authenticationToken));
        // Only search a subset of the requested CAs if requested
        if (!request.getCaIds().isEmpty()) {
            authorizedLocalCaIds.retainAll(request.getCaIds());
        }
        final List<String> issuerDns = new ArrayList<>();
        // TODO: Check EEP authorization once this is implemented
        for (final int caId : authorizedLocalCaIds) {
            try {
                final String issuerDn = CertTools.stringToBCDNString(StringTools.strip(caSession.getCAInfoInternal(caId).getSubjectDN()));
                issuerDns.add(issuerDn);
            } catch (CADoesntExistsException e) {
                log.warn("CA went missing during search operation. " + e.getMessage());
            }
        }
        if (issuerDns.isEmpty()) {
            // Empty response since there were no authorized CAs
            if (log.isDebugEnabled()) {
                log.debug("Client '"+authenticationToken+"' was not authorized to any of the requested CAs and the search request will be dropped.");
            }
            return response;
        }
        final List<Integer> authorizedCpIds = new ArrayList<>(certificateProfileSession.getAuthorizedCertificateProfileIds(authenticationToken, 0));
        if (!request.getCpIds().isEmpty()) {
            authorizedCpIds.retainAll(request.getCpIds());
        }
        if (authorizedCpIds.isEmpty()) {
            // Empty response since there were no authorized Certificate Profiles
            if (log.isDebugEnabled()) {
                log.debug("Client '"+authenticationToken+"' was not authorized to any of the requested CPs and the search request will be dropped.");
            }
            return response;
        }
        final Collection<Integer> authorizedEepIds = new ArrayList<>(endEntityProfileSession.getAuthorizedEndEntityProfileIds(authenticationToken, AccessRulesConstants.VIEW_END_ENTITY));
        if (!request.getEepIds().isEmpty()) {
            authorizedEepIds.retainAll(request.getEepIds());
        }
        if (authorizedEepIds.isEmpty()) {
            // Empty response since there were no authorized End Entity Profiles
            if (log.isDebugEnabled()) {
                log.debug("Client '"+authenticationToken+"' was not authorized to any of the requested EEPs and the search request will be dropped.");
            }
            return response;
        }
        final String genericSearchString = request.getGenericSearchString();
        final String genericSearchStringDec = request.getGenericSearchStringAsDecimal();
        final String genericSearchStringHex = request.getGenericSearchStringAsHex();
        StringBuilder sb = new StringBuilder("SELECT a.fingerprint FROM CertificateData a WHERE (a.issuerDN IN (:issuerDN))");
        if (!genericSearchString.isEmpty()) {
            sb.append(" AND (a.username LIKE :username OR a.subjectDN LIKE :subjectDN");
            if (genericSearchStringDec!=null) {
                sb.append(" OR a.serialNumber LIKE :serialNumberDec");
            }
            if (genericSearchStringDec==null && genericSearchStringHex!=null) {
                sb.append(" OR a.serialNumber LIKE :serialNumberHex");
            }
            sb.append(")");
        }
        if (request.getExpiresAfter()<Long.MAX_VALUE) {
            sb.append(" AND (a.expireDate > :expiresAfter)");
        }
        if (request.getExpiresBefore()>0) {
            sb.append(" AND (a.expireDate < :expiresBefore)");
        }
        // NOTE: updateTime is not indexed.. we might want to disallow such search.
        if (request.getRevokedAfter()<Long.MAX_VALUE) {
            sb.append(" AND (a.revocationDate > :revokedAfter)");
        }
        if (request.getRevokedBefore()>0L) {
            sb.append(" AND (a.revocationDate < :revokedBefore)");
        }
        if (!request.getStatuses().isEmpty()) {
            sb.append(" AND (a.status IN (:status))");
            if ((request.getStatuses().contains(CertificateConstants.CERT_REVOKED) || request.getStatuses().contains(CertificateConstants.CERT_ARCHIVED)) &&
                    !request.getRevocationReasons().isEmpty()) {
                sb.append(" AND (a.revocationReason IN (:revocationReason))");
            }
        }
        sb.append(" AND (a.certificateProfileId IN (:certificateProfileId))");
        //sb.append(" AND (a.endEntityProfileId IN (:endEntityProfileId))");
        final Query query = entityManager.createQuery(sb.toString());
        query.setParameter("issuerDN", issuerDns);
        query.setParameter("certificateProfileId", authorizedCpIds);
        //query.setParameter("endEntityProfileId", authorizedEepIds);
        if (log.isDebugEnabled()) {
            log.debug(" issuerDN: " + Arrays.toString(issuerDns.toArray()));
            log.debug(" certificateProfileId: " + Arrays.toString(authorizedCpIds.toArray()));
            log.debug(" endEntityProfileId: " + Arrays.toString(authorizedEepIds.toArray()));
        }
        if (!genericSearchString.isEmpty()) {
            query.setParameter("username", "%" + genericSearchString + "%");
            query.setParameter("subjectDN", "%" + genericSearchString + "%");
            if (genericSearchStringDec!=null) {
                query.setParameter("serialNumberDec", genericSearchStringDec);
                if (log.isDebugEnabled()) {
                    log.debug(" serialNumberDec: " + genericSearchStringDec);
                }
            }
            if (genericSearchStringDec==null && genericSearchStringHex!=null) {
                query.setParameter("serialNumberHex", genericSearchStringHex);
                if (log.isDebugEnabled()) {
                    log.debug(" serialNumberHex: " + genericSearchStringHex);
                }
            }
        }
        if (request.getExpiresAfter()<Long.MAX_VALUE) {
            query.setParameter("expiresAfter", request.getExpiresAfter());
        }
        if (request.getExpiresBefore()>0) {
            query.setParameter("expiresBefore", request.getExpiresBefore());
        }
        if (request.getRevokedAfter()<Long.MAX_VALUE) {
            query.setParameter("revokedAfter", request.getRevokedAfter());
        }
        if (request.getRevokedBefore()>0L) {
            query.setParameter("revokedBefore", request.getRevokedBefore());
        }
        if (!request.getStatuses().isEmpty()) {
            query.setParameter("status", request.getStatuses());
            if ((request.getStatuses().contains(CertificateConstants.CERT_REVOKED) || request.getStatuses().contains(CertificateConstants.CERT_ARCHIVED)) &&
                    !request.getRevocationReasons().isEmpty()) {
                query.setParameter("revocationReason", request.getRevocationReasons());
            }
        }
        final int maxResults = Math.min(1000, request.getMaxResults());
        query.setMaxResults(maxResults);
        @SuppressWarnings("unchecked")
        final List<String> fingerprints = query.getResultList();
        if (log.isDebugEnabled()) {
            log.debug("Certificate search query: " + sb.toString() + " LIMIT " + maxResults + " → " + query.getResultList().size() + " results.");
        }
        for (final String fingerprint : fingerprints) {
            response.getCdws().add(certificateStoreSession.getCertificateData(fingerprint));
        }
        response.setMightHaveMoreResults(fingerprints.size()==maxResults);
        return response;
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
    
    @Override
    public final Map<Integer, String> getAuthorizedEndEntityProfileIdsToNameMap(AuthenticationToken authenticationToken) {
        final Collection<Integer> authorizedEepIds = endEntityProfileSession.getAuthorizedEndEntityProfileIds(authenticationToken, AccessRulesConstants.VIEW_END_ENTITY);
        final Map<Integer, String> idToNameMap = endEntityProfileSession.getEndEntityProfileIdToNameMap();
        final Map<Integer, String> authorizedIdToNameMap = new HashMap<>();
        for (final Integer eepId : authorizedEepIds) {
            authorizedIdToNameMap.put(eepId, idToNameMap.get(eepId));
        }
        return authorizedIdToNameMap;
    }
    
    @Override
    public final Map<Integer, String> getAuthorizedCertificateProfileIdsToNameMap(AuthenticationToken authenticationToken) {
        final List<Integer> authorizedCpIds = new ArrayList<>(certificateProfileSession.getAuthorizedCertificateProfileIds(authenticationToken, 0));
        // There is no reason to return a certificate profile if it is not present in one of the authorized EEPs
        final Collection<Integer> authorizedEepIds = endEntityProfileSession.getAuthorizedEndEntityProfileIds(authenticationToken, AccessRulesConstants.VIEW_END_ENTITY);
        final Set<Integer> cpIdsInAuthorizedEeps = new HashSet<>(); 
        for (final Integer eepId : authorizedEepIds) {
            final EndEntityProfile eep = endEntityProfileSession.getEndEntityProfile(eepId);
            for (final String availableCertificateProfileId : eep.getAvailableCertificateProfileIds()) {
                cpIdsInAuthorizedEeps.add(Integer.parseInt(availableCertificateProfileId));
            }
        }
        authorizedCpIds.retainAll(cpIdsInAuthorizedEeps);
        final Map<Integer, String> idToNameMap = certificateProfileSession.getCertificateProfileIdToNameMap();
        final Map<Integer, String> authorizedIdToNameMap = new HashMap<>();
        for (final Integer cpId : authorizedCpIds) {
            authorizedIdToNameMap.put(cpId, idToNameMap.get(cpId));
        }
        return authorizedIdToNameMap;
    }
    
    @Override
    public final Map<String, EndEntityProfile> getAuthorizedEndEntityProfiles(AuthenticationToken authenticationToken){
        Collection<Integer> ids = endEntityProfileSession.getAuthorizedEndEntityProfileIds(authenticationToken, AccessRulesConstants.VIEW_END_ENTITY);
        Map<Integer, String> idToNameMap = endEntityProfileSession.getEndEntityProfileIdToNameMap();
        Map<String, EndEntityProfile> authorizedEndEntityProfiles = new HashMap<String, EndEntityProfile>(ids.size());
        for(Integer id: ids){
            authorizedEndEntityProfiles.put(idToNameMap.get(id), endEntityProfileSession.getEndEntityProfile(id));
        }
        return authorizedEndEntityProfiles;
    }

    @Override
    public Map<String, CertificateProfile> getAvailableCertificateProfiles(AuthenticationToken authenticationToken, String[] certificateProfilesIds)
            throws AuthorizationDeniedException {
        Map<String, CertificateProfile> availableCertificateProfiles = new HashMap<String, CertificateProfile>();
        for(String certificateProfileId: certificateProfilesIds){
            CertificateProfile certificateProfile = certificateProfileSession.getCertificateProfile(Integer.parseInt(certificateProfileId));
            String certificateProfilename = certificateProfileSession.getCertificateProfileName(Integer.parseInt(certificateProfileId));
            availableCertificateProfiles.put(certificateProfilename, certificateProfile);
        }
        
        return availableCertificateProfiles;
    }
}
