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

import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateParsingException;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

import javax.ejb.EJB;
import javax.ejb.RemoveException;
import javax.ejb.Stateless;
import javax.ejb.TransactionAttribute;
import javax.ejb.TransactionAttributeType;
import javax.persistence.EntityManager;
import javax.persistence.PersistenceContext;
import javax.persistence.PersistenceException;
import javax.persistence.Query;
import javax.persistence.QueryTimeoutException;

import org.apache.log4j.Logger;
import org.cesecore.authentication.AuthenticationFailedException;
import org.cesecore.authentication.tokens.AuthenticationToken;
import org.cesecore.authentication.tokens.X509CertificateAuthenticationToken;
import org.cesecore.authorization.AuthorizationDeniedException;
import org.cesecore.authorization.access.AccessSet;
import org.cesecore.authorization.control.AccessControlSessionLocal;
import org.cesecore.certificates.ca.CAConstants;
import org.cesecore.certificates.ca.CADoesntExistsException;
import org.cesecore.certificates.ca.CAInfo;
import org.cesecore.certificates.ca.CAOfflineException;
import org.cesecore.certificates.ca.CaSessionLocal;
import org.cesecore.certificates.ca.IllegalNameException;
import org.cesecore.certificates.ca.IllegalValidityException;
import org.cesecore.certificates.ca.InvalidAlgorithmException;
import org.cesecore.certificates.ca.SignRequestException;
import org.cesecore.certificates.ca.SignRequestSignatureException;
import org.cesecore.certificates.certificate.CertificateConstants;
import org.cesecore.certificates.certificate.CertificateCreateException;
import org.cesecore.certificates.certificate.CertificateDataWrapper;
import org.cesecore.certificates.certificate.CertificateRevokeException;
import org.cesecore.certificates.certificate.CertificateStoreSessionLocal;
import org.cesecore.certificates.certificate.IllegalKeyException;
import org.cesecore.certificates.certificate.certextensions.CertificateExtensionException;
import org.cesecore.certificates.certificate.exception.CertificateSerialNumberException;
import org.cesecore.certificates.certificate.exception.CustomCertificateSerialNumberException;
import org.cesecore.certificates.certificate.request.PKCS10RequestMessage;
import org.cesecore.certificates.certificate.request.RequestMessageUtils;
import org.cesecore.certificates.certificate.request.ResponseMessage;
import org.cesecore.certificates.certificate.request.X509ResponseMessage;
import org.cesecore.certificates.certificateprofile.CertificateProfile;
import org.cesecore.certificates.certificateprofile.CertificateProfileSessionLocal;
import org.cesecore.certificates.endentity.EndEntityInformation;
import org.cesecore.certificates.endentity.ExtendedInformation;
import org.cesecore.config.CesecoreConfiguration;
import org.cesecore.config.GlobalCesecoreConfiguration;
import org.cesecore.configuration.GlobalConfigurationSessionLocal;
import org.cesecore.keys.token.CryptoTokenOfflineException;
import org.cesecore.util.CertTools;
import org.cesecore.util.StringTools;
import org.ejbca.core.EjbcaException;
import org.ejbca.core.ejb.approval.ApprovalExecutionSessionLocal;
import org.ejbca.core.ejb.approval.ApprovalSessionLocal;
import org.ejbca.core.ejb.ca.auth.EndEntityAuthenticationSessionLocal;
import org.ejbca.core.ejb.ca.sign.SignSessionLocal;
import org.ejbca.core.ejb.hardtoken.HardTokenSessionLocal;
import org.ejbca.core.ejb.keyrecovery.KeyRecoverySessionLocal;
import org.ejbca.core.ejb.ra.EndEntityAccessSessionLocal;
import org.ejbca.core.ejb.ra.EndEntityExistsException;
import org.ejbca.core.ejb.ra.EndEntityManagementSessionLocal;
import org.ejbca.core.ejb.ra.NoSuchEndEntityException;
import org.ejbca.core.ejb.ra.raadmin.EndEntityProfileSessionLocal;
import org.ejbca.core.model.SecConst;
import org.ejbca.core.model.approval.AdminAlreadyApprovedRequestException;
import org.ejbca.core.model.approval.Approval;
import org.ejbca.core.model.approval.ApprovalDataText;
import org.ejbca.core.model.approval.ApprovalDataVO;
import org.ejbca.core.model.approval.ApprovalException;
import org.ejbca.core.model.approval.ApprovalRequest;
import org.ejbca.core.model.approval.ApprovalRequestExecutionException;
import org.ejbca.core.model.approval.ApprovalRequestExpiredException;
import org.ejbca.core.model.approval.ApprovalStep;
import org.ejbca.core.model.approval.SelfApprovalException;
import org.ejbca.core.model.approval.WaitingForApprovalException;
import org.ejbca.core.model.approval.approvalrequests.AddEndEntityApprovalRequest;
import org.ejbca.core.model.approval.approvalrequests.EditEndEntityApprovalRequest;
import org.ejbca.core.model.approval.type.AccumulativeApprovalProfile;
import org.ejbca.core.model.authorization.AccessRulesConstants;
import org.ejbca.core.model.ca.AuthLoginException;
import org.ejbca.core.model.ca.AuthStatusException;
import org.ejbca.core.model.era.RaApprovalResponseRequest.MetadataResponse;
import org.ejbca.core.model.ra.NotFoundException;
import org.ejbca.core.model.ra.raadmin.EndEntityProfile;
import org.ejbca.core.model.ra.raadmin.UserDoesntFullfillEndEntityProfile;
import org.ejbca.core.model.util.GenerateToken;
import org.ejbca.util.query.ApprovalMatch;
import org.ejbca.util.query.BasicMatch;
import org.ejbca.util.query.IllegalQueryException;

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
    private ApprovalSessionLocal approvalSession;
    @EJB
    private ApprovalExecutionSessionLocal approvalExecutionSession;
    @EJB
    private AccessControlSessionLocal accessControlSession;
    @EJB
    private CaSessionLocal caSession;
    @EJB
    private CertificateProfileSessionLocal certificateProfileSession;
    @EJB
    private CertificateStoreSessionLocal certificateStoreSession;
    @EJB
    private EndEntityAccessSessionLocal endEntityAccessSession;
    @EJB
    private EndEntityProfileSessionLocal endEntityProfileSession;
    @EJB
    private EndEntityManagementSessionLocal endEntityManagementSessionLocal;
    @EJB
    private GlobalConfigurationSessionLocal globalConfigurationSession;
    @EJB
    private HardTokenSessionLocal hardTokenSession;
    @EJB
    private KeyRecoverySessionLocal keyRecoverySessionLocal;
    @EJB
    private SignSessionLocal signSessionLocal;
    @EJB
    private EndEntityAuthenticationSessionLocal endEntityAuthenticationSessionLocal;

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
    
    private ApprovalDataVO getApprovalData(AuthenticationToken authenticationToken, final int id) {
        final org.ejbca.util.query.Query query = new org.ejbca.util.query.Query(org.ejbca.util.query.Query.TYPE_APPROVALQUERY);
        query.add(ApprovalMatch.MATCH_WITH_UNIQUEID, BasicMatch.MATCH_TYPE_EQUALS, Integer.toString(id));
        
        final List<ApprovalDataVO> approvals;
        try {
            approvals = approvalSession.query(authenticationToken, query, 0, 100, "", "", ""); // authorization checks are performed afterwards
        } catch (AuthorizationDeniedException e) {
            // Not currently ever thrown by query()
            throw new IllegalStateException(e);
        } catch (IllegalQueryException e) {
            throw new IllegalStateException("Query for approval request failed: " + e.getMessage(), e);
        }
        
        if (approvals.isEmpty()) {
            return null;
        }
        
        return approvals.iterator().next();
    }
    
    /** Gets the complete text representation of a request (unlike ApprovalRequest.getNewRequestDataAsText which doesn't do any database queries) */
    private List<ApprovalDataText> getRequestDataAsText(final AuthenticationToken authenticationToken, final ApprovalDataVO approval) {
        final ApprovalRequest approvalRequest = approval.getApprovalRequest();
        if (approvalRequest instanceof EditEndEntityApprovalRequest) {
            return ((EditEndEntityApprovalRequest)approvalRequest).getNewRequestDataAsText(caSession, endEntityProfileSession, certificateProfileSession, hardTokenSession);
        } else if (approvalRequest instanceof AddEndEntityApprovalRequest) {
            return ((AddEndEntityApprovalRequest)approvalRequest).getNewRequestDataAsText(caSession, endEntityProfileSession, certificateProfileSession, hardTokenSession);
        } else {
            return approvalRequest.getNewRequestDataAsText(authenticationToken);
        }
    }
    
    private RaEditableRequestData getRequestEditableData(final AuthenticationToken authenticationToken, final ApprovalDataVO advo) {
        final ApprovalRequest approvalRequest = advo.getApprovalRequest();
        final RaEditableRequestData editableData = new RaEditableRequestData();
        EndEntityInformation userdata = null;
        
        if (approvalRequest instanceof EditEndEntityApprovalRequest) {
            final EditEndEntityApprovalRequest req = (EditEndEntityApprovalRequest)approvalRequest;
            userdata = req.getNewEndEntityInformation();
        } else if (approvalRequest instanceof AddEndEntityApprovalRequest) {
            final AddEndEntityApprovalRequest req = (AddEndEntityApprovalRequest)approvalRequest;
            userdata = req.getEndEntityInformation();
        }
        // TODO handle more types or approval requests?
        
        if (userdata != null) {
            editableData.setUsername(userdata.getUsername());
            editableData.setEmail(userdata.getEmail());
            editableData.setSubjectDN(userdata.getDN());
            editableData.setSubjectAltName(userdata.getSubjectAltName());
            if (userdata.getExtendedinformation() != null) {
                final ExtendedInformation ei = userdata.getExtendedinformation();
                editableData.setSubjectDirAttrs(ei.getSubjectDirectoryAttributes());
            }
        }
        
        return editableData;
    }

    @Override
    public RaApprovalRequestInfo getApprovalRequest(final AuthenticationToken authenticationToken, final int id) {
        final ApprovalDataVO advo = getApprovalData(authenticationToken, id);
        if (advo == null) {
            return null;
        }
        return getApprovalRequest(authenticationToken, advo);
    }
    
    private RaApprovalRequestInfo getApprovalRequest(final AuthenticationToken authenticationToken, final ApprovalDataVO advo) {
        // The values are used to check if a request belongs to us or not
        String adminCertSerial = null; 
        String adminCertIssuer = null;
        if (authenticationToken instanceof X509CertificateAuthenticationToken) {
            final X509CertificateAuthenticationToken certAuth = (X509CertificateAuthenticationToken) authenticationToken;
            final X509Certificate cert = certAuth.getCertificate();
            adminCertSerial = CertTools.getSerialNumberAsString(cert);
            adminCertIssuer = CertTools.getIssuerDN(cert);
        }
        
        // By getting the CA we perform an implicit auth check
        final String caName;
        if (advo.getCAId() == ApprovalDataVO.ANY_CA) {
            caName = null;
        } else {
            try {
                final CAInfo cainfo = caSession.getCAInfo(authenticationToken, advo.getCAId());
                caName = cainfo.getName();
            } catch (AuthorizationDeniedException e) {
                if (log.isDebugEnabled()) {
                    log.debug("Authorization to CA " + advo.getCAId() + " was denied. Returning null instead of the approval with id " + advo.getId());
                }
                return null;
            } catch (CADoesntExistsException e) {
                throw new IllegalStateException("Appproval request references CA id " + advo.getCAId() + " which doesn't exist");
            }
        }
        
        // Get request data as text
        final List<ApprovalDataText> requestData = getRequestDataAsText(authenticationToken, advo);
        
        // Editable data
        final RaEditableRequestData editableData = getRequestEditableData(authenticationToken, advo);
        
        // TODO perform ee profile and approval profile authorization checks also
        
        return new RaApprovalRequestInfo(authenticationToken, adminCertIssuer, adminCertSerial, caName, advo, requestData, editableData);
        
    }

    @Override
    public RaApprovalRequestInfo editApprovalRequest(final AuthenticationToken authenticationToken, final RaApprovalEditRequest edit) throws AuthorizationDeniedException {
        if (!(authenticationToken instanceof X509CertificateAuthenticationToken)) {
            throw new AuthorizationDeniedException("Can only edit an approval request with certificate authentication");
        }
        final X509CertificateAuthenticationToken x509admin = (X509CertificateAuthenticationToken) authenticationToken;
        final String adminIssuerDN = CertTools.getIssuerDN(x509admin.getCertificate());
        final String adminSerial = CertTools.getSerialNumberAsString(x509admin.getCertificate());
        
        // TODO perhaps move into ApprovalSessionBean?
        // TODO fix audit logging. currently logs as remove + add
        final int id = edit.getId();
        final ApprovalDataVO advo = getApprovalData(authenticationToken, id);
        if (advo == null) {
            log.debug("Approval not found in editApprovalRequest");
            return null;
        }
        if (advo.getStatus() != ApprovalDataVO.STATUS_WAITINGFORAPPROVAL) {
            throw new IllegalStateException("Was not in waiting for approval state");
        }
        
        if (!advo.getApprovals().isEmpty()) {
            throw new IllegalStateException("Can't edit a request that has one or more approvals");
        }
        
        final ApprovalRequest approvalRequest = advo.getApprovalRequest();
        final RaEditableRequestData editData = edit.getEditableData();
        
        if (approvalRequest instanceof AddEndEntityApprovalRequest) {
            // TODO validate the values and check that they aren't null?
            final AddEndEntityApprovalRequest addReq = (AddEndEntityApprovalRequest) approvalRequest;
            final EndEntityInformation userdata = addReq.getEndEntityInformation();
            userdata.setUsername(editData.getUsername());
            userdata.setEmail(editData.getEmail());
            userdata.setDN(editData.getSubjectDN());
            userdata.setSubjectAltName(editData.getSubjectAltName());
            if (userdata.getExtendedinformation() == null && editData.getSubjectDirAttrs() != null) {
                userdata.setExtendedinformation(new ExtendedInformation());
            }
            final ExtendedInformation ei = userdata.getExtendedinformation();
            ei.setSubjectDirectoryAttributes(editData.getSubjectDirAttrs());
        } else {
            // TODO implement more types of requests
            throw new IllegalStateException("Editing of this type of request is not implemented: " + approvalRequest.getClass().getName());
        }
        
        // Remove the old approval
        try {
            approvalSession.removeApprovalRequest(authenticationToken, id);
        } catch (ApprovalException e) {
            // TODO remove and add to throws declaration
            throw new RuntimeException(e);
        }
        
        try {
            // Re-add the approval. This should leave the requesting admin unchanged
            approvalRequest.setBlacklistedAdminIssuerDN(adminIssuerDN); // admins may not approve requests they have edited
            approvalRequest.setBlacklistedAdminSerial(adminSerial);
            approvalSession.addApprovalRequest(authenticationToken, approvalRequest);
        } catch (ApprovalException e) {
            // TODO remove and add to throws declaration
            throw new RuntimeException(e);
        }
        
        final int newCalculatedId = approvalRequest.generateApprovalId();
        final Collection<ApprovalDataVO> advosNew = approvalSession.findApprovalDataVO(authenticationToken, newCalculatedId);
        if (advosNew.isEmpty()) {
            throw new IllegalStateException("Approval with calculated id (approvalId) " + newCalculatedId + " could not be found");
        }
        final ApprovalDataVO advoNew = advosNew.iterator().next();
        return getApprovalRequest(authenticationToken, advoNew);
    }
    
    @Override
    public boolean addRequestResponse(AuthenticationToken authenticationToken, RaApprovalResponseRequest requestResponse) throws AuthorizationDeniedException, ApprovalException, ApprovalRequestExpiredException, ApprovalRequestExecutionException, AdminAlreadyApprovedRequestException, SelfApprovalException {
        final ApprovalDataVO advo = getApprovalData(authenticationToken, requestResponse.getId());
        if (advo == null) {
            // Return false so the next master api backend can see if it can handle the approval
            return false;
        }
        // Convert RA request steps into approval steps
        final boolean isAccumulativeOnly = advo.getApprovalRequest().getApprovalProfile().getApprovalProfileType() instanceof AccumulativeApprovalProfile;
        final Approval approval = new Approval(requestResponse.getComment());
        final ApprovalStep approvalStep;
        if (isAccumulativeOnly) {
            approvalStep = null;
            if (requestResponse.getStepId() != -1) {
                throw new IllegalStateException("An approval step was provided for a plain accumulative approval request");
            }
        } else {
            if (requestResponse.getStepId() == -1) {
                throw new IllegalStateException("No approval step was provided for partitioned approval request");
            }
            approvalStep = advo.getApprovalRequest().getApprovalStep(requestResponse.getStepId());
            for (final MetadataResponse metadata : requestResponse.getMetadataList()) {
                approvalStep.updateOneMetadataValue(metadata.getMetadataId(), metadata.getOptionValue(), metadata.getOptionNote());
            }
        }
        
        switch (requestResponse.getAction()) {
        case APPROVE:
            approvalExecutionSession.approve(authenticationToken, advo.getApprovalId(), approval, approvalStep, isAccumulativeOnly);
            return true;
        case REJECT:
            approvalSession.reject(authenticationToken, advo.getApprovalId(), approval, approvalStep, isAccumulativeOnly);
            return true;
        case SAVE:
            throw new UnsupportedOperationException("Saving without approving or rejecting is not yet implemented");
        default:
            throw new IllegalStateException("Invalid action");
        }
    }
    
    @Override
    public RaRequestsSearchResponse searchForApprovalRequests(final AuthenticationToken authenticationToken, final RaRequestsSearchRequest request) {
        final RaRequestsSearchResponse response = new RaRequestsSearchResponse();
        final List<CAInfo> authorizedCas = getAuthorizedCas(authenticationToken);
        if (authorizedCas.size() == 0) {
            return response; // not authorized to any CAs. return empty response
        }
        final Map<Integer,String> caIdToNameMap = new HashMap<>();
        for (final CAInfo cainfo : authorizedCas) {
            caIdToNameMap.put(cainfo.getCAId(), cainfo.getName());
        }
        
        if (!request.isSearchingWaitingForMe() && !request.isSearchingPending() && !request.isSearchingHistorical()) {
            return response; // not searching for anything. return empty response
        }
        
        // The values are used to check if a request belongs to us or not
        String adminCertSerial = null; 
        String adminCertIssuer = null;
        if (authenticationToken instanceof X509CertificateAuthenticationToken) {
            final X509CertificateAuthenticationToken certAuth = (X509CertificateAuthenticationToken) authenticationToken;
            final X509Certificate cert = certAuth.getCertificate();
            adminCertSerial = CertTools.getSerialNumberAsString(cert);
            adminCertIssuer = CertTools.getIssuerDN(cert);
        }
        
        // Filtering
        final org.ejbca.util.query.Query query = new org.ejbca.util.query.Query(org.ejbca.util.query.Query.TYPE_APPROVALQUERY);
        // TODO should we limit to add/revoke end entity requests also?
        if (request.isSearchingHistorical()) {
            // Everything except waiting and "approved" (which means approved but not excecuted)
            query.add(ApprovalMatch.MATCH_WITH_STATUS, BasicMatch.MATCH_TYPE_EQUALS, Integer.toString(ApprovalDataVO.STATUS_EXECUTED));
            query.add(org.ejbca.util.query.Query.CONNECTOR_OR);
            query.add(ApprovalMatch.MATCH_WITH_STATUS, BasicMatch.MATCH_TYPE_EQUALS, Integer.toString(ApprovalDataVO.STATUS_EXECUTIONDENIED));
            query.add(org.ejbca.util.query.Query.CONNECTOR_OR);
            query.add(ApprovalMatch.MATCH_WITH_STATUS, BasicMatch.MATCH_TYPE_EQUALS, Integer.toString(ApprovalDataVO.STATUS_EXECUTIONFAILED));
            query.add(org.ejbca.util.query.Query.CONNECTOR_OR);
            query.add(ApprovalMatch.MATCH_WITH_STATUS, BasicMatch.MATCH_TYPE_EQUALS, Integer.toString(ApprovalDataVO.STATUS_REJECTED));
            query.add(org.ejbca.util.query.Query.CONNECTOR_OR);
            query.add(ApprovalMatch.MATCH_WITH_STATUS, BasicMatch.MATCH_TYPE_EQUALS, Integer.toString(ApprovalDataVO.STATUS_EXPIRED));
            query.add(org.ejbca.util.query.Query.CONNECTOR_OR);
            query.add(ApprovalMatch.MATCH_WITH_STATUS, BasicMatch.MATCH_TYPE_EQUALS, Integer.toString(ApprovalDataVO.STATUS_EXPIREDANDNOTIFIED));
        }
        if (request.isSearchingWaitingForMe() || request.isSearchingPending()) {
            if (request.isSearchingHistorical()) {
                query.add(org.ejbca.util.query.Query.CONNECTOR_OR);
            }
            query.add(ApprovalMatch.MATCH_WITH_STATUS, BasicMatch.MATCH_TYPE_EQUALS, Integer.toString(ApprovalDataVO.STATUS_WAITINGFORAPPROVAL));
            query.add(org.ejbca.util.query.Query.CONNECTOR_OR);
            // Certain requests (not add end entity) can require the requesting admin to retry the action
            query.add(ApprovalMatch.MATCH_WITH_STATUS, BasicMatch.MATCH_TYPE_EQUALS, Integer.toString(ApprovalDataVO.STATUS_APPROVED));
        }
        
        // Build CA authorization string (a part of the query) 
        StringBuilder sb = new StringBuilder();
        sb.append("caId IN (");
        boolean first = true;
        for (CAInfo ca : authorizedCas) {
            if (!first) {
                sb.append(',');
            }
            sb.append(ca.getCAId());
            first = false;
        }
        sb.append(')');
        final String caAuthorizationString = sb.toString();
        
        // TODO perform ee profile and approval profile authorization checks
        final String endEntityProfileAuthorizationString = "";
        final String approvalProfileAuthorizationString = "";
        
        // TODO use a more efficient method that doesn't use a starting index?
        //      perhaps modify the query method?
        //      or create a query manually? (in this case we need to construct either the ApprovalDataVO, or the RaApprovalRequestInfo directly)
        final List<ApprovalDataVO> approvals;
        try {
            approvals = approvalSession.query(authenticationToken, query, 0, 100, caAuthorizationString, endEntityProfileAuthorizationString, approvalProfileAuthorizationString);
        } catch (AuthorizationDeniedException e) {
            // Not currently ever thrown by query()
            throw new IllegalStateException(e);
        } catch (IllegalQueryException e) {
            throw new IllegalStateException("Query for approval requests failed: " + e.getMessage(), e);
        }
        
        if (approvals.size() >= 100) {
            response.setMightHaveMoreResults(true);
        }
        
        for (final ApprovalDataVO advo : approvals) {
            final List<ApprovalDataText> requestDataLite = advo.getApprovalRequest().getNewRequestDataAsText(authenticationToken); // this method isn't guaranteed to return the full information
            final RaEditableRequestData editableData = getRequestEditableData(authenticationToken, advo);
            final RaApprovalRequestInfo ari = new RaApprovalRequestInfo(authenticationToken, adminCertIssuer, adminCertSerial, caIdToNameMap.get(advo.getCAId()), advo, requestDataLite, editableData);
            if (!ari.isPending() && request.isSearchingPending()) { continue; } // XXX untested code!
            if (!ari.isWaitingForMe() && request.isSearchingWaitingForMe()) { continue; }
            // XXX It seems that the query() method filters out approvals that the current admin isn't involved in. How to handle historical steps in this case? And pending steps?
            response.getApprovalRequests().add(ari);
        }
        return response;
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
    
    @SuppressWarnings("unchecked")
    @Override
    public RaCertificateSearchResponse searchForCertificates(AuthenticationToken authenticationToken, RaCertificateSearchRequest request) {
        final RaCertificateSearchResponse response = new RaCertificateSearchResponse();
        final List<Integer> authorizedLocalCaIds = new ArrayList<>(caSession.getAuthorizedCaIds(authenticationToken));
        // Only search a subset of the requested CAs if requested
        if (!request.getCaIds().isEmpty()) {
            authorizedLocalCaIds.retainAll(request.getCaIds());
        }
        final List<String> issuerDns = new ArrayList<>();
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
        // Check Certificate Profile authorization
        final List<Integer> authorizedCpIds = new ArrayList<>(certificateProfileSession.getAuthorizedCertificateProfileIds(authenticationToken, 0));
        final boolean accessAnyCpAvailable = authorizedCpIds.containsAll(certificateProfileSession.getCertificateProfileIdToNameMap().keySet());
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
        // Check End Entity Profile authorization
        final Collection<Integer> authorizedEepIds = new ArrayList<>(endEntityProfileSession.getAuthorizedEndEntityProfileIds(authenticationToken, AccessRulesConstants.VIEW_END_ENTITY));
        final boolean accessAnyEepAvailable = authorizedEepIds.containsAll(endEntityProfileSession.getEndEntityProfileIdToNameMap().keySet());
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
        final StringBuilder sb = new StringBuilder("SELECT a.fingerprint FROM CertificateData a WHERE (a.issuerDN IN (:issuerDN))");
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
        // NOTE: revocationDate is not indexed.. we might want to disallow such search.
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
        // Don't constrain results to certain certificate profiles if root access is available and "any" CP is requested
        if (!accessAnyCpAvailable || !request.getCpIds().isEmpty()) {
            sb.append(" AND (a.certificateProfileId IN (:certificateProfileId))");
        }
        // Don't constrain results to certain end entity profiles if root access is available and "any" EEP is requested
        if (!accessAnyEepAvailable || !request.getEepIds().isEmpty()) {
            sb.append(" AND (a.endEntityProfileId IN (:endEntityProfileId))");
        }
        final Query query = entityManager.createQuery(sb.toString());
        query.setParameter("issuerDN", issuerDns);
        if (!accessAnyCpAvailable || !request.getCpIds().isEmpty()) {
            query.setParameter("certificateProfileId", authorizedCpIds);
        }
        if (!accessAnyEepAvailable || !request.getEepIds().isEmpty()) {
            query.setParameter("endEntityProfileId", authorizedEepIds);
        }
        if (log.isDebugEnabled()) {
            log.debug(" issuerDN: " + Arrays.toString(issuerDns.toArray()));
            if (!accessAnyCpAvailable || !request.getCpIds().isEmpty()) {
                log.debug(" certificateProfileId: " + Arrays.toString(authorizedCpIds.toArray()));
            } else {
                log.debug(" certificateProfileId: Any (even deleted) profile(s) due to root access.");
            }
            if (!accessAnyEepAvailable || !request.getEepIds().isEmpty()) {
                log.debug(" endEntityProfileId: " + Arrays.toString(authorizedEepIds.toArray()));
            } else {
                log.debug(" endEntityProfileId: Any (even deleted) profile(s) due to root access.");
            }
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
        final int maxResults = Math.min(getGlobalCesecoreConfiguration().getMaximumQueryCount(), request.getMaxResults());
        query.setMaxResults(maxResults);
        /* Try to use the non-portable hint (depends on DB and JDBC driver) to specify how long in milliseconds the query may run. Possible behaviors:
         * - The hint is ignored
         * - A QueryTimeoutException is thrown
         * - A PersistenceException is thrown (and the transaction which don't have here is marked for roll-back)
         */
        final long queryTimeout = getGlobalCesecoreConfiguration().getMaximumQueryTimeout();
        if (queryTimeout>0L) {
            query.setHint("javax.persistence.query.timeout", String.valueOf(queryTimeout));
        }
        final List<String> fingerprints;
        try {
            fingerprints = query.getResultList();
            for (final String fingerprint : fingerprints) {
                response.getCdws().add(certificateStoreSession.getCertificateData(fingerprint));
            }
            response.setMightHaveMoreResults(fingerprints.size()==maxResults);
            if (log.isDebugEnabled()) {
                log.debug("Certificate search query: " + sb.toString() + " LIMIT " + maxResults + " \u2192 " + fingerprints.size() + " results. queryTimeout=" + queryTimeout + "ms");
            }
        } catch (QueryTimeoutException e) {
            log.info("Requested search query by " + authenticationToken +  " took too long. Query was " + e.getQuery().toString() + ". " + e.getMessage());
            response.setMightHaveMoreResults(true);
        } catch (PersistenceException e) {
            log.info("Requested search query by " + authenticationToken +  " failed, possibly due to timeout. " + e.getMessage());
            response.setMightHaveMoreResults(true);
        }
        return response;
    }

    @SuppressWarnings("unchecked")
    @Override
    public RaEndEntitySearchResponse searchForEndEntities(AuthenticationToken authenticationToken, RaEndEntitySearchRequest request) {
        final RaEndEntitySearchResponse response = new RaEndEntitySearchResponse();
        final List<Integer> authorizedLocalCaIds = new ArrayList<>(caSession.getAuthorizedCaIds(authenticationToken));
        // Only search a subset of the requested CAs if requested
        if (!request.getCaIds().isEmpty()) {
            authorizedLocalCaIds.retainAll(request.getCaIds());
        }
        if (authorizedLocalCaIds.isEmpty()) {
            // Empty response since there were no authorized CAs
            if (log.isDebugEnabled()) {
                log.debug("Client '"+authenticationToken+"' was not authorized to any of the requested CAs and the search request will be dropped.");
            }
            return response;
        }
        // Check Certificate Profile authorization
        final List<Integer> authorizedCpIds = new ArrayList<>(certificateProfileSession.getAuthorizedCertificateProfileIds(authenticationToken, 0));
        final boolean accessAnyCpAvailable = authorizedCpIds.containsAll(certificateProfileSession.getCertificateProfileIdToNameMap().keySet());
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
        // Check End Entity Profile authorization
        final Collection<Integer> authorizedEepIds = new ArrayList<>(endEntityProfileSession.getAuthorizedEndEntityProfileIds(authenticationToken, AccessRulesConstants.VIEW_END_ENTITY));
        final boolean accessAnyEepAvailable = authorizedEepIds.containsAll(endEntityProfileSession.getEndEntityProfileIdToNameMap().keySet());
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
        final StringBuilder sb = new StringBuilder("SELECT a.username FROM UserData a WHERE (a.caId IN (:caId))");
        if (!genericSearchString.isEmpty()) {
            sb.append(" AND (a.username LIKE :username OR a.subjectDN LIKE :subjectDN OR a.subjectAltName LIKE :subjectAltName)");
        }
        if (request.getModifiedAfter()<Long.MAX_VALUE) {
            sb.append(" AND (a.timeModified > :modifiedAfter)");
        }
        if (request.getModifiedBefore()>0L) {
            sb.append(" AND (a.timeModified < :modifiedBefore)");
        }
        if (!request.getStatuses().isEmpty()) {
            sb.append(" AND (a.status IN (:status))");
        }
        // Don't constrain results to certain end entity profiles if root access is available and "any" CP is requested
        if (!accessAnyCpAvailable || !request.getCpIds().isEmpty()) {
            sb.append(" AND (a.certificateProfileId IN (:certificateProfileId))");
        }
        // Don't constrain results to certain end entity profiles if root access is available and "any" EEP is requested
        if (!accessAnyEepAvailable || !request.getEepIds().isEmpty()) {
            sb.append(" AND (a.endEntityProfileId IN (:endEntityProfileId))");
        }
        final Query query = entityManager.createQuery(sb.toString());
        query.setParameter("caId", authorizedLocalCaIds);
        if (!accessAnyCpAvailable || !request.getCpIds().isEmpty()) {
            query.setParameter("certificateProfileId", authorizedCpIds);
        }
        if (!accessAnyEepAvailable || !request.getEepIds().isEmpty()) {
            query.setParameter("endEntityProfileId", authorizedEepIds);
        }
        if (log.isDebugEnabled()) {
            log.debug(" CA IDs: " + Arrays.toString(authorizedLocalCaIds.toArray()));
            if (!accessAnyCpAvailable || !request.getCpIds().isEmpty()) {
                log.debug(" certificateProfileId: " + Arrays.toString(authorizedCpIds.toArray()));
            } else {
                log.debug(" certificateProfileId: Any (even deleted) profile(s) due to root access.");
            }
            if (!accessAnyEepAvailable || !request.getEepIds().isEmpty()) {
                log.debug(" endEntityProfileId: " + Arrays.toString(authorizedEepIds.toArray()));
            } else {
                log.debug(" endEntityProfileId: Any (even deleted) profile(s) due to root access.");
            }
        }
        if (!genericSearchString.isEmpty()) {
            query.setParameter("username", "%" + genericSearchString + "%");
            query.setParameter("subjectDN", "%" + genericSearchString + "%");
            query.setParameter("subjectAltName", "%" + genericSearchString + "%");
        }
        if (request.getModifiedAfter()<Long.MAX_VALUE) {
            query.setParameter("modifiedAfter", request.getModifiedAfter());
        }
        if (request.getModifiedBefore()>0) {
            query.setParameter("modifiedBefore", request.getModifiedBefore());
        }
        if (!request.getStatuses().isEmpty()) {
            query.setParameter("status", request.getStatuses());
        }
        final int maxResults = Math.min(getGlobalCesecoreConfiguration().getMaximumQueryCount(), request.getMaxResults());
        query.setMaxResults(maxResults);
        /* Try to use the non-portable hint (depends on DB and JDBC driver) to specify how long in milliseconds the query may run. Possible behaviors:
         * - The hint is ignored
         * - A QueryTimeoutException is thrown
         * - A PersistenceException is thrown (and the transaction which don't have here is marked for roll-back)
         */
        final long queryTimeout = getGlobalCesecoreConfiguration().getMaximumQueryTimeout();
        if (queryTimeout>0L) {
            query.setHint("javax.persistence.query.timeout", String.valueOf(queryTimeout));
        }
        final List<String> usernames;
        try {
            usernames = query.getResultList();
            for (final String username : usernames) {
                response.getEndEntities().add(endEntityAccessSession.findUser(username));
            }
            response.setMightHaveMoreResults(usernames.size()==maxResults);
            if (log.isDebugEnabled()) {
                log.debug("Certificate search query: " + sb.toString() + " LIMIT " + maxResults + " \u2192 " + usernames.size() + " results. queryTimeout=" + queryTimeout + "ms");
            }
        } catch (QueryTimeoutException e) {
            log.info("Requested search query by " + authenticationToken +  " took too long. Query was " + e.getQuery().toString() + ". " + e.getMessage());
            response.setMightHaveMoreResults(true);
        } catch (PersistenceException e) {
            log.info("Requested search query by " + authenticationToken +  " failed, possibly due to timeout. " + e.getMessage());
            response.setMightHaveMoreResults(true);
        }
        return response;
    }
    
    @Override
    public Map<Integer, String> getAuthorizedEndEntityProfileIdsToNameMap(AuthenticationToken authenticationToken) {
        final Collection<Integer> authorizedEepIds = endEntityProfileSession.getAuthorizedEndEntityProfileIds(authenticationToken, AccessRulesConstants.VIEW_END_ENTITY);
        final Map<Integer, String> idToNameMap = endEntityProfileSession.getEndEntityProfileIdToNameMap();
        final Map<Integer, String> authorizedIdToNameMap = new HashMap<>();
        for (final Integer eepId : authorizedEepIds) {
            authorizedIdToNameMap.put(eepId, idToNameMap.get(eepId));
        }
        return authorizedIdToNameMap;
    }
    
    @Override
    public Map<Integer, String> getAuthorizedCertificateProfileIdsToNameMap(AuthenticationToken authenticationToken) {
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
    public IdNameHashMap<EndEntityProfile> getAuthorizedEndEntityProfiles(AuthenticationToken authenticationToken){
        Collection<Integer> ids = endEntityProfileSession.getAuthorizedEndEntityProfileIds(authenticationToken, AccessRulesConstants.EDIT_END_ENTITY);
        Map<Integer, String> idToNameMap = endEntityProfileSession.getEndEntityProfileIdToNameMap();
        IdNameHashMap<EndEntityProfile> authorizedEndEntityProfiles = new IdNameHashMap<>();
        for(Integer id: ids){
            authorizedEndEntityProfiles.put(id, idToNameMap.get(id), endEntityProfileSession.getEndEntityProfile(id));
        }
        return authorizedEndEntityProfiles;
    }
    
    @Override
    public IdNameHashMap<CertificateProfile> getAuthorizedCertificateProfiles(AuthenticationToken authenticationToken){
        IdNameHashMap<CertificateProfile> authorizedCertificateProfiles = new IdNameHashMap<>();
        List<Integer> authorizedCertificateProfileIds = certificateProfileSession.getAuthorizedCertificateProfileIds(authenticationToken, CertificateConstants.CERTTYPE_ENDENTITY);
        for(Integer certificateProfileId : authorizedCertificateProfileIds){
            CertificateProfile certificateProfile = certificateProfileSession.getCertificateProfile(certificateProfileId);
            String certificateProfilename = certificateProfileSession.getCertificateProfileName(certificateProfileId);
            authorizedCertificateProfiles.put(certificateProfileId, certificateProfilename, certificateProfile);
        }
        
        return authorizedCertificateProfiles;
    }
    
    @Override
    public IdNameHashMap<CAInfo> getAuthorizedCAInfos(AuthenticationToken authenticationToken) {
        IdNameHashMap<CAInfo> authorizedCAInfos = new IdNameHashMap<>();
        List<CAInfo> authorizedCAInfosList = caSession.getAuthorizedAndNonExternalCaInfos(authenticationToken);
        for(CAInfo caInfo : authorizedCAInfosList){
            if (caInfo.getStatus() == CAConstants.CA_ACTIVE) {
                authorizedCAInfos.put(caInfo.getCAId(), caInfo.getName(), caInfo);
            }
        }
        return authorizedCAInfos;
    }
    
    @Override
    public boolean addUser(final AuthenticationToken admin, final EndEntityInformation endEntity, final boolean clearpwd) throws AuthorizationDeniedException,
        EndEntityExistsException, WaitingForApprovalException{
        try {
            endEntityManagementSessionLocal.addUser(admin, endEntity, clearpwd);
        } catch (CADoesntExistsException | UserDoesntFullfillEndEntityProfile | EjbcaException e) {
            log.error(e);
            return false;
        }
        
        return endEntityAccessSession.findUser(endEntity.getUsername()) != null;
    }
    
    @Override
    public void deleteUser(final AuthenticationToken admin, final String username) throws AuthorizationDeniedException{
        try {
            endEntityManagementSessionLocal.deleteUser(admin, username);
        } catch (NotFoundException | RemoveException e) {
            log.error(e);
        }
    }
    
    @Override
    public EndEntityInformation findUser(final AuthenticationToken admin, String username) throws AuthorizationDeniedException{
        return endEntityAccessSession.findUser(username);
    }
    
    @Override
    public KeyStore generateKeystore(final AuthenticationToken admin, final EndEntityInformation endEntity, String keyLength, String keyAlg) throws AuthorizationDeniedException, KeyStoreException{
        GenerateToken tgen = new GenerateToken(endEntityAuthenticationSessionLocal, endEntityAccessSession, endEntityManagementSessionLocal, caSession, keyRecoverySessionLocal, signSessionLocal);
        try {
            KeyStore ks = tgen.generateOrKeyRecoverToken(admin, endEntity.getUsername(), endEntity.getPassword(), endEntity.getCAId(), keyLength, keyAlg, endEntity.getTokenType() == SecConst.TOKEN_SOFT_JKS, false, false, false, endEntity.getEndEntityProfileId());
            return ks;
        } catch (Exception e) {
            throw new KeyStoreException(e);
        }
    }
    
    @Override
    public byte[] createCertificate(AuthenticationToken authenticationToken, EndEntityInformation endEntity, byte[] certificateRequest)throws AuthorizationDeniedException{
        PKCS10RequestMessage req = null;
        req = RequestMessageUtils.genPKCS10RequestMessage(certificateRequest);
        req.setUsername(endEntity.getUsername());
        req.setPassword(endEntity.getPassword());
        
        ResponseMessage resp;
        try {
            resp = signSessionLocal.createCertificate(authenticationToken, req, X509ResponseMessage.class, null);
            X509Certificate cert = CertTools.getCertfromByteArray(resp.getResponseMessage(), X509Certificate.class);
            return cert.getEncoded();
        } catch (NoSuchEndEntityException | CustomCertificateSerialNumberException | CryptoTokenOfflineException | IllegalKeyException
                | CADoesntExistsException | SignRequestException | SignRequestSignatureException | AuthStatusException | AuthLoginException
                | IllegalNameException | CertificateCreateException | CertificateRevokeException | CertificateSerialNumberException
                | IllegalValidityException | CAOfflineException | InvalidAlgorithmException | CertificateExtensionException e) {
            log.error(e);
        } catch (CertificateParsingException | CertificateEncodingException e) {
            throw new IllegalStateException("Internal error with creating X509Certificate from CertificateResponseMessage");
        }
        return null;
    }
    
    @Override
    public byte[] createPkcs7(AuthenticationToken authenticationToken, X509Certificate certificate, boolean includeChain) throws AuthorizationDeniedException{
        try {
            return signSessionLocal.createPKCS7(authenticationToken, certificate, includeChain);
        } catch (CADoesntExistsException | SignRequestSignatureException e) {
            log.error(e);
            return null;
        }
    }

    private GlobalCesecoreConfiguration getGlobalCesecoreConfiguration() {
        return (GlobalCesecoreConfiguration) globalConfigurationSession.getCachedConfiguration(GlobalCesecoreConfiguration.CESECORE_CONFIGURATION_ID);
    }
}
