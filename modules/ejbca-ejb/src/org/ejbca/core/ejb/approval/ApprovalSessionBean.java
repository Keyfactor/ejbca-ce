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

package org.ejbca.core.ejb.approval;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.ObjectOutputStream;
import java.io.Serializable;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.Date;
import java.util.Iterator;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

import javax.annotation.PostConstruct;
import javax.annotation.Resource;
import javax.ejb.EJB;
import javax.ejb.SessionContext;
import javax.ejb.Stateless;
import javax.ejb.TransactionAttribute;
import javax.ejb.TransactionAttributeType;
import javax.persistence.EntityManager;
import javax.persistence.PersistenceContext;
import javax.persistence.TypedQuery;

import org.apache.commons.lang.StringUtils;
import org.apache.log4j.Logger;
import org.cesecore.ErrorCode;
import org.cesecore.audit.enums.EventStatus;
import org.cesecore.audit.log.SecurityEventsLoggerSessionLocal;
import org.cesecore.authentication.AuthenticationFailedException;
import org.cesecore.authentication.tokens.AuthenticationToken;
import org.cesecore.certificates.ca.ApprovalRequestType;
import org.cesecore.certificates.ca.CaSessionLocal;
import org.cesecore.certificates.certificate.CertificateInfo;
import org.cesecore.certificates.certificate.CertificateStoreSessionLocal;
import org.cesecore.certificates.certificateprofile.CertificateProfile;
import org.cesecore.certificates.certificateprofile.CertificateProfileSessionLocal;
import org.cesecore.certificates.endentity.EndEntityInformation;
import org.cesecore.configuration.GlobalConfigurationSessionLocal;
import org.cesecore.jndi.JndiConstants;
import org.cesecore.util.Base64;
import org.cesecore.util.CertTools;
import org.cesecore.util.CryptoProviderTools;
import org.cesecore.util.ProfileID;
import org.cesecore.util.ValueExtractor;
import org.cesecore.util.ui.DynamicUiProperty;
import org.cesecore.util.ui.MultiLineString;
import org.ejbca.config.EjbcaConfiguration;
import org.ejbca.core.ejb.audit.enums.EjbcaEventTypes;
import org.ejbca.core.ejb.audit.enums.EjbcaModuleTypes;
import org.ejbca.core.ejb.audit.enums.EjbcaServiceTypes;
import org.ejbca.core.ejb.ra.EndEntityAccessSessionLocal;
import org.ejbca.core.model.InternalEjbcaResources;
import org.ejbca.core.model.approval.Approval;
import org.ejbca.core.model.approval.ApprovalDataText;
import org.ejbca.core.model.approval.ApprovalDataVO;
import org.ejbca.core.model.approval.ApprovalException;
import org.ejbca.core.model.approval.ApprovalNotificationParameterGenerator;
import org.ejbca.core.model.approval.ApprovalRequest;
import org.ejbca.core.model.approval.ApprovalRequestExpiredException;
import org.ejbca.core.model.approval.approvalrequests.ActivateCATokenApprovalRequest;
import org.ejbca.core.model.approval.approvalrequests.AddEndEntityApprovalRequest;
import org.ejbca.core.model.approval.approvalrequests.ChangeStatusEndEntityApprovalRequest;
import org.ejbca.core.model.approval.approvalrequests.EditEndEntityApprovalRequest;
import org.ejbca.core.model.approval.approvalrequests.GenerateTokenApprovalRequest;
import org.ejbca.core.model.approval.approvalrequests.KeyRecoveryApprovalRequest;
import org.ejbca.core.model.approval.approvalrequests.RevocationApprovalRequest;
import org.ejbca.core.model.approval.approvalrequests.ViewHardTokenDataApprovalRequest;
import org.ejbca.core.model.approval.profile.ApprovalPartition;
import org.ejbca.core.model.approval.profile.ApprovalPartitionWorkflowState;
import org.ejbca.core.model.approval.profile.ApprovalProfile;
import org.ejbca.core.model.approval.profile.ApprovalStep;
import org.ejbca.core.model.approval.profile.PartitionedApprovalProfile;
import org.ejbca.util.mail.MailException;
import org.ejbca.util.mail.MailSender;
import org.ejbca.util.query.IllegalQueryException;
import org.ejbca.util.query.Query;

/**
 * Keeps track of approval requests and their approval or rejects.
 * 
 * @version $Id$
 */
@Stateless(mappedName = JndiConstants.APP_JNDI_PREFIX + "ApprovalSessionRemote")
@TransactionAttribute(TransactionAttributeType.REQUIRED)
public class ApprovalSessionBean implements ApprovalSessionLocal, ApprovalSessionRemote {

    private static final Logger log = Logger.getLogger(ApprovalSessionBean.class);

    /** Internal localization of logs and errors */
    private static final InternalEjbcaResources intres = InternalEjbcaResources.getInstance();

    @PersistenceContext(unitName = "ejbca")
    private EntityManager entityManager;
    @Resource
    private SessionContext sessionContext;
    
    @EJB
    private ApprovalProfileSessionLocal approvalProfileSession;
    @EJB
    private CaSessionLocal caSession;
    @EJB
    private CertificateProfileSessionLocal certificateProfileSession;
    @EJB
    private CertificateStoreSessionLocal certificateStoreSession;
    @EJB
    private EndEntityAccessSessionLocal endEntityAccessSession;
    @EJB
    private GlobalConfigurationSessionLocal globalConfigurationSession;
    @EJB
    private SecurityEventsLoggerSessionLocal auditSession;
    
    private ApprovalSessionLocal approvalSession;
    
    @PostConstruct
    public void postConstruct() {
        // Install BouncyCastle provider if not available
        CryptoProviderTools.installBCProviderIfNotAvailable();
        // It is not possible to @EJB-inject our self on all application servers so we need to do a lookup
        approvalSession = sessionContext.getBusinessObject(ApprovalSessionLocal.class);
    }
    
    @Override
    public int addApprovalRequest(AuthenticationToken admin, ApprovalRequest approvalRequest) throws ApprovalException {
    	if (log.isTraceEnabled()) {
    		log.trace(">addApprovalRequest: hash="+approvalRequest.generateApprovalId());
    	}
        int approvalId = approvalRequest.generateApprovalId();
        Integer requestId = 0;
        ApprovalDataVO data = findNonExpiredApprovalRequest(approvalId);
        if (data != null) {
            String msg = intres.getLocalizedMessage("approval.alreadyexists", approvalId);
            log.info(msg);
            throw new ApprovalException(ErrorCode.APPROVAL_ALREADY_EXISTS, msg);
        } else {
            // There exists no approval request with status waiting. Add a new one
            try {
                requestId = findFreeApprovalId();
                final ApprovalData approvalData = new ApprovalData(requestId);
                updateApprovalData(approvalData, approvalRequest);
                entityManager.persist(approvalData);
                final ApprovalProfile approvalProfile = approvalRequest.getApprovalProfile();
                sendApprovalNotifications(approvalRequest, approvalProfile, approvalData, false);
                String msg = intres.getLocalizedMessage("approval.addedwaiting", requestId);
                final Map<String, Object> details = new LinkedHashMap<String, Object>();
                details.put("msg", msg);
                List<ApprovalDataText> texts = approvalRequest.getNewRequestDataAsText(admin);
                for (ApprovalDataText text : texts) {
                    details.put(text.getHeader(), text.getData());                    
                }
                auditSession.log(EjbcaEventTypes.APPROVAL_ADD, EventStatus.SUCCESS, EjbcaModuleTypes.APPROVAL, EjbcaServiceTypes.EJBCA,
                        admin.toString(), String.valueOf(approvalRequest.getCAId()), null, null, details);
            } catch (Exception e1) {
                String msg = intres.getLocalizedMessage("approval.erroradding", requestId);
                log.error(msg, e1);
                final Map<String, Object> details = new LinkedHashMap<String, Object>();
                details.put("msg", msg);
                details.put("Error", e1.getMessage());
                auditSession.log(EjbcaEventTypes.APPROVAL_ADD, EventStatus.FAILURE, EjbcaModuleTypes.APPROVAL, EjbcaServiceTypes.EJBCA,
                        admin.toString(), String.valueOf(approvalRequest.getCAId()), null, null, details);
            }
        }
        if (log.isTraceEnabled()) {
        	log.trace("<addApprovalRequest: hash="+approvalRequest.generateApprovalId()+", id="+requestId);
        }
        return requestId;
    }
    
    @Override
    public void editApprovalRequest(final AuthenticationToken admin, final int id, final ApprovalRequest approvalRequest) throws ApprovalException {
        if (log.isTraceEnabled()) {
            log.trace(">editApprovalRequest: hash="+approvalRequest.generateApprovalId()+", id="+id);
        }
        final ApprovalData ad = findById(id);
        if (ad == null) {
            throw new ApprovalException("The approval request does not exist");
        }
        if (ad.getStatus() != ApprovalDataVO.STATUS_WAITINGFORAPPROVAL) {
            throw new ApprovalException("The approval request is not in the Waiting For Approval state, and cannot be edited");
        }
        try {
            approvalRequest.addEditedByAdmin(admin);
            updateApprovalData(ad, approvalRequest);
            String msg = intres.getLocalizedMessage("approval.edited", id);
            final Map<String, Object> details = new LinkedHashMap<>();
            details.put("msg", msg);
            List<ApprovalDataText> texts = approvalRequest.getNewRequestDataAsText(admin);
            for (ApprovalDataText text : texts) {
                details.put(text.getHeader(), text.getData());                    
            }
            auditSession.log(EjbcaEventTypes.APPROVAL_EDIT, EventStatus.SUCCESS, EjbcaModuleTypes.APPROVAL, EjbcaServiceTypes.EJBCA,
                    admin.toString(), String.valueOf(approvalRequest.getCAId()), null, null, details);
        } catch (Exception e) {
            String msg = intres.getLocalizedMessage("approval.errorediting", id);
            log.error(msg, e);
            final Map<String, Object> details = new LinkedHashMap<>();
            details.put("msg", msg);
            details.put("Error", e.getMessage());
            auditSession.log(EjbcaEventTypes.APPROVAL_EDIT, EventStatus.FAILURE, EjbcaModuleTypes.APPROVAL, EjbcaServiceTypes.EJBCA,
                    admin.toString(), String.valueOf(approvalRequest.getCAId()), null, null, details);
        }
        if (log.isTraceEnabled()) {
            log.trace(">editApprovalRequest: hash="+approvalRequest.generateApprovalId()+", id="+id);
        }
    }
    
    /** Updates the ApprovalData from the given approval request, and initializes the list of approvals to an empty list. */
    @SuppressWarnings("deprecation")
    private void updateApprovalData(final ApprovalData approvalData, final ApprovalRequest approvalRequest) {
        approvalData.setApprovalid(approvalRequest.generateApprovalId());
        approvalData.setApprovaltype(approvalRequest.getApprovalType());
        approvalData.setEndentityprofileid(approvalRequest.getEndEntityProfileId());
        approvalData.setCaid(approvalRequest.getCAId());
        if (approvalRequest.getRequestAdminCert() != null) {
            approvalData.setReqadmincertissuerdn(CertTools.getIssuerDN(approvalRequest.getRequestAdminCert()));
            approvalData.setReqadmincertsn(CertTools.getSerialNumberAsString(approvalRequest.getRequestAdminCert()));
        }
        setApprovalRequest(approvalData, approvalRequest);
        setApprovals(approvalData, new ArrayList<Approval>());
        approvalData.setExpiredate((new Date()).getTime() + approvalRequest.getRequestValidity());
        //Kept for legacy reasons
        approvalData.setRemainingapprovals(approvalRequest.getNumOfRequiredApprovals());
    }

    @Override
    public void removeApprovalRequest(AuthenticationToken admin, int id) {
        if (log.isTraceEnabled()) {
            log.trace(">removeApprovalRequest: id="+id);
        }
        try {
            ApprovalData ad = findById(Integer.valueOf(id));
            if (ad != null) {
                entityManager.remove(ad);
                final String detailsMsg = intres.getLocalizedMessage("approval.removed", id);
                auditSession.log(EjbcaEventTypes.APPROVAL_REMOVE, EventStatus.SUCCESS, EjbcaModuleTypes.APPROVAL, EjbcaServiceTypes.EJBCA,
                        admin.toString(), String.valueOf(ad.getCaid()), null, null, detailsMsg);
            } else {
                String msg = intres.getLocalizedMessage("approval.notexist", id);
                log.info(msg);
                throw new ApprovalException(ErrorCode.APPROVAL_REQUEST_ID_NOT_EXIST, msg);
            }
        } catch (Exception e) {
            String msg = intres.getLocalizedMessage("approval.errorremove", id);
            final Map<String, Object> details = new LinkedHashMap<String, Object>();
            details.put("msg", msg);
            details.put("error", e.getMessage());
            auditSession.log(EjbcaEventTypes.APPROVAL_REMOVE, EventStatus.FAILURE, EjbcaModuleTypes.APPROVAL, EjbcaServiceTypes.EJBCA,
                    admin.toString(), null, null, null, details);
            log.error("Error removing approval request", e);
        }
        if (log.isTraceEnabled()) {
            log.trace("<removeApprovalRequest: id="+id);
        }
    }

    @Override
    public int isApproved(int approvalId, int step) throws ApprovalException, ApprovalRequestExpiredException {
        if (log.isTraceEnabled()) {
            log.trace(">isApproved, approvalId: " + approvalId);
        }
        int retval = ApprovalDataVO.STATUS_EXPIREDANDNOTIFIED;
        Collection<ApprovalData> result = findByApprovalId(approvalId);
        if (result.size() == 0) {
            throw new ApprovalException(ErrorCode.APPROVAL_REQUEST_ID_NOT_EXIST, "Approval request with id : " + approvalId + " does not exist");
        }
        if (log.isTraceEnabled()) {
            log.trace("Found "+result.size()+" ApprovalData with id "+approvalId);
        }
        for(ApprovalData adl : result) {
            if (log.isTraceEnabled()) {
                log.trace("Checking if ApprovalRequest of type "+adl.getApprovaltype()+" with databaseID "+adl.getId()+" and approvalID "+adl.getApprovalid()+" is approved: "+adl.getStatus());
            }
            retval = isApproved(adl, step);
            if (adl.getStatus() == ApprovalDataVO.STATUS_WAITINGFORAPPROVAL || adl.getStatus() == ApprovalDataVO.STATUS_APPROVED
                    || adl.getStatus() == ApprovalDataVO.STATUS_REJECTED) {
                break;
            }
        }
        if (log.isTraceEnabled()) {
            log.trace("<isApproved, result: " + retval);
        }
        return retval;
    }

    @Override
    public int isApproved(int approvalId) throws ApprovalException, ApprovalRequestExpiredException {
        return isApproved(approvalId, 0);
    }

    @Override
    public int getStatus(int approvalId) throws ApprovalException {
        final TypedQuery<ApprovalData> query = entityManager.createQuery(
                "SELECT a FROM ApprovalData a WHERE a.approvalid=:approvalId", ApprovalData.class);
        query.setParameter("approvalId", approvalId);
        List<ApprovalData> resultList = query.getResultList();
        if (resultList.size() > 0) {
            return resultList.get(0).getStatus();
        } else {
            throw new ApprovalException("Approval request not found in database");
        }
    }
    
    @Override
    public void markAsStepDone(int approvalId, int step) throws ApprovalException, ApprovalRequestExpiredException {
        if (log.isTraceEnabled()) {
            log.trace(">markAsStepDone, approvalId: " + approvalId + ", step " + step);
        }
        Collection<ApprovalData> result = findByApprovalId(approvalId);
        if (result.size() == 0) {
            throw new ApprovalException(ErrorCode.APPROVAL_REQUEST_ID_NOT_EXIST, "Approval request with id : " + approvalId + " does not exist");
        }
        for(ApprovalData adl : result) {
            markStepAsDone(adl, step);
        }
        if (log.isTraceEnabled()) {
            log.trace("<markAsStepDone, approvalId: " + approvalId + ", step " + step);
        }
    }
    
    @TransactionAttribute(TransactionAttributeType.SUPPORTS)
    @Override
    public List<ApprovalData> findWaitingForApprovalApprovalDataLocal() {
        final TypedQuery<ApprovalData> query = entityManager
                .createQuery("SELECT a FROM ApprovalData a WHERE a.status=" + ApprovalDataVO.STATUS_WAITINGFORAPPROVAL, ApprovalData.class);
        List<ApprovalData> result = query.getResultList();
        return result;
    }

    @TransactionAttribute(TransactionAttributeType.SUPPORTS)
    @Override
    public ApprovalDataVO findNonExpiredApprovalRequest(int approvalId) {
        ApprovalDataVO retval = null;
        ApprovalData data = findNonExpiredApprovalDataLocal(approvalId);
        if (data != null) {
            retval = data.getApprovalDataVO();
        }
        return retval;
    }

    @TransactionAttribute(TransactionAttributeType.SUPPORTS)
    @Override
    public ApprovalData findNonExpiredApprovalDataLocal(int approvalId) {
        ApprovalData retval = null;
        Collection<ApprovalData> result = findByApprovalIdNonExpired(approvalId);
        if (log.isDebugEnabled()) {
        	log.debug("Found number of approvalIdNonExpired: " + result.size());
        }
        for (ApprovalData next : result) {
            ApprovalDataVO data = next.getApprovalDataVO();
            if (data.getStatus() == ApprovalDataVO.STATUS_WAITINGFORAPPROVAL || data.getStatus() == ApprovalDataVO.STATUS_APPROVED
                    || data.getStatus() == ApprovalDataVO.STATUS_REJECTED) {
                retval = next;
            }
        }
        return retval;
    }

    @TransactionAttribute(TransactionAttributeType.SUPPORTS)
    @Override
    public List<ApprovalDataVO> findApprovalDataVO(int approvalId) {
        if (log.isTraceEnabled()) {
            log.trace(">findApprovalDataVO: hash="+approvalId);
        }
        ArrayList<ApprovalDataVO> retval = new ArrayList<ApprovalDataVO>();
        Collection<ApprovalData> result = findByApprovalId(approvalId);
        for (ApprovalData adl : result) {
            retval.add(adl.getApprovalDataVO());
        }
        log.trace("<findApprovalDataVO");
        return retval;
    }

    @TransactionAttribute(TransactionAttributeType.SUPPORTS)
    @Override
    public List<ApprovalDataVO> query(final Query query, int index, int numberofrows, String caAuthorizationString,
            String endEntityProfileAuthorizationString) throws IllegalQueryException {
        log.trace(">query()");
        // Check if query is legal.
        if (query != null && !query.isLegalQuery()) {
            throw new IllegalQueryException();
        }
        final String queryString = (query != null ? query.getQueryString() : "1 = 1");
        final List<ApprovalDataVO> ret = queryInternal(queryString, index, numberofrows, caAuthorizationString, endEntityProfileAuthorizationString, null);
        log.trace("<query()");
        return ret;
    }
    
    @TransactionAttribute(TransactionAttributeType.SUPPORTS)
    @Override
    public List<ApprovalDataVO> queryByStatus(final boolean includeUnfinished, final boolean includeProcessed, final boolean includeExpired,
            final Date startDate, final Date endDate, final Date expiresBefore, int index, int numberofrows, String caAuthorizationString,
            String endEntityProfileAuthorizationString) {
        log.trace(">queryByStatus()");
        
        if (!includeUnfinished && !includeProcessed && !includeExpired) {
            throw new IllegalArgumentException("At least one of includeUnfinished, includeProcessed or includeExpired must be true");
        }
        
        final StringBuilder sb = new StringBuilder();
        
        String orderByString = null;
        sb.append('(');
        boolean first = true;
        if (includeUnfinished || includeExpired) {
            sb.append('(');
            if (includeUnfinished && includeExpired) {
                // No additional filtering
            } else if (!includeExpired) {
                // Do not include expired requests
                sb.append("expireDate >= ");
                sb.append(new Date().getTime());
                sb.append(" AND ");
            } else if (includeExpired) {
                sb.append("expireDate < ");
                sb.append(new Date().getTime());
                sb.append(" AND ");
            } else if (expiresBefore != null) {
                // Only include expired requests
                sb.append("expireDate < ");
                sb.append(new Date().getTime());
                sb.append(" AND ");
            }
            if (expiresBefore != null) {
                sb.append("expireDate < ");
                sb.append(expiresBefore.getTime());
                sb.append(" AND ");
            }
            // "STATUS_APPROVED" means that the request is still waiting to be executed by the requester
            sb.append("status IN (" + ApprovalDataVO.STATUS_WAITINGFORAPPROVAL + ", " + ApprovalDataVO.STATUS_APPROVED + (includeExpired ? ", " + ApprovalDataVO.STATUS_EXPIRED + ", " + ApprovalDataVO.STATUS_EXPIREDANDNOTIFIED : "") + "))");
            orderByString = "ORDER BY requestDate ASC"; // oldest first
            first = false;
        }
        if (includeProcessed) {
            if (!first) { sb.append(" OR "); }
            sb.append("status IN (" + ApprovalDataVO.STATUS_EXECUTED + ", " + ApprovalDataVO.STATUS_EXECUTIONDENIED + ", " +
                    ApprovalDataVO.STATUS_EXECUTIONFAILED + ", " + ApprovalDataVO.STATUS_REJECTED + ")");
            orderByString = "ORDER BY requestDate DESC"; // most recently created first
            first = false;
        }
        sb.append(')');
        
        if (startDate != null) {
            sb.append(" AND requestDate >= " + startDate.getTime());
        }
        if (endDate != null) {
            sb.append(" AND requestDate < " + endDate.getTime()); 
        }
        final List<ApprovalDataVO> ret = queryInternal(sb.toString(), index, numberofrows,
                caAuthorizationString, endEntityProfileAuthorizationString,
                orderByString);
        log.trace("<queryByStatus()");
        return ret;
    }
    
    private List<ApprovalDataVO> queryInternal(final String query, int index, int numberofrows, String caAuthorizationString,
            String endEntityProfileAuthorizationString, final String orderByString) {
        log.trace(">queryInternal()");
        String customQuery = "(" + query + ")";
        if (StringUtils.isNotEmpty(caAuthorizationString)) {
            customQuery += " AND " + caAuthorizationString;
        }
        if (StringUtils.isNotEmpty(endEntityProfileAuthorizationString)) {
            customQuery += " AND " + endEntityProfileAuthorizationString;
        }
        if (StringUtils.isNotEmpty(orderByString)) {
            customQuery += " " + orderByString;
        }
        
        final List<ApprovalData> approvalDataList = findByCustomQuery(index, numberofrows, customQuery);
        final List<ApprovalDataVO> returnData = new ArrayList<>(approvalDataList.size());
        for (ApprovalData approvalData : approvalDataList) {
            final ApprovalDataVO approvalInformation = approvalData.getApprovalDataVO();
            //Perform a lazy upgrade of incoming approval requests produced prior to 6.5.0, which will lack a reference to an approval profile. The 
            //upgrade procedure will have created the required approval profiles. 
            ApprovalRequest approvalRequest = approvalInformation.getApprovalRequest();
            if(approvalRequest.getApprovalProfile() == null) {
                if(log.isDebugEnabled()) {
                    log.debug("Attempting to upgrade approval with ID " + approvalData.getApprovalid() 
                    + " to 6.6.0+ status by retrieving an approval profile from either the certificate profile or the CA.");
                }
                ApprovalProfile approvalProfile;

                //For the sake of upgrade, we're forced to use instanceof to find the relevant certificate profile ID, based on the behavior in 
                //6.5.x 
                CertificateProfile certificateProfile = null;
                if (approvalRequest instanceof ActivateCATokenApprovalRequest) {
                    //See legacy instantiation in CAAdminSessionBean
                    certificateProfile = certificateProfileSession
                            .getCertificateProfile(caSession.getCAInfoInternal(approvalRequest.getCAId()).getCertificateProfileId());
                } else if (approvalRequest instanceof AddEndEntityApprovalRequest) {
                    //See legacy instantiation in EndEntityManagementSessionBean
                    certificateProfile = certificateProfileSession.getCertificateProfile(
                            ((AddEndEntityApprovalRequest) approvalRequest).getEndEntityInformation().getCertificateProfileId());
                } else if (approvalRequest instanceof ChangeStatusEndEntityApprovalRequest) {
                    //See legacy instantiation in EndEntityManagementSessionBean
                    EndEntityInformation endEntityInformation = endEntityAccessSession
                            .findUser(((ChangeStatusEndEntityApprovalRequest) approvalRequest).getUsername());
                    certificateProfile = certificateProfileSession.getCertificateProfile(endEntityInformation.getCertificateProfileId());
                } else if (approvalRequest instanceof EditEndEntityApprovalRequest) {
                    //See legacy instantiation in EndEntityManagementSessionBean
                    certificateProfile = certificateProfileSession.getCertificateProfile(
                            ((EditEndEntityApprovalRequest) approvalRequest).getNewEndEntityInformation().getCertificateProfileId());
                } else if (approvalRequest instanceof GenerateTokenApprovalRequest) {
                    //TODO: Handle 100% uptime for hard token requests under ECA-5078
                } else if (approvalRequest instanceof KeyRecoveryApprovalRequest) {
                    //See legacy instantiation in KeyRecoverySessionBean
                    final CertificateInfo certificateInfor = certificateStoreSession.getCertificateInfo(
                            CertTools.getFingerprintAsString(((KeyRecoveryApprovalRequest) approvalRequest).getRequestAdminCert()));
                    certificateProfile = certificateProfileSession.getCertificateProfile(certificateInfor.getCertificateProfileId());
                } else if (approvalRequest instanceof RevocationApprovalRequest) {
                    //See legacy instantiation in RevocationSessionBean
                    EndEntityInformation endEntityInformation = endEntityAccessSession
                            .findUser(((RevocationApprovalRequest) approvalRequest).getUsername());
                    certificateProfile = certificateProfileSession.getCertificateProfile(endEntityInformation.getCertificateProfileId());
                } else if (approvalRequest instanceof ViewHardTokenDataApprovalRequest) {
                    //TODO: Handle 100% uptime for hard token requests under ECA-5078
                }
                approvalProfile = approvalProfileSession.getApprovalProfileForAction(
                        ApprovalRequestType.getFromIntegerValue(approvalRequest.getApprovalRequestType()),
                        caSession.getCAInfoInternal(approvalRequest.getCAId()), certificateProfile);
             
                approvalRequest.setApprovalProfile(approvalProfile);
                approvalInformation.setApprovalRequest(approvalRequest);
                approvalSession.updateApprovalRequest(approvalData.getId(), approvalRequest);
                if (log.isDebugEnabled()) {
                    log.debug("Upgraded approval with ID " + approvalData.getApprovalid() + " to 6.6.0+ by setting approval profile with ID "
                            + approvalProfile != null ? (approvalProfile.getProfileId() + "(" + approvalProfile.getProfileName() + ")") : "(no approval profile)" + ".");
                }
            }
            returnData.add(approvalInformation);         
        }
        log.trace("<queryInternal()");
        return returnData;
    }

    @Override
    @TransactionAttribute(TransactionAttributeType.SUPPORTS)
    public void sendApprovalNotifications(final ApprovalRequest approvalRequest, final ApprovalProfile approvalProfile,
            final ApprovalData approvalData, final boolean expired) {
        try {
            final List<Approval> approvalsPerformed = approvalData.getApprovals();
            // When adding a new approval request the list of performed approvals is empty
            final Approval lastApproval = approvalsPerformed.isEmpty() ? null : approvalsPerformed.get(approvalsPerformed.size()-1);
            // If all steps has been satisfied, the ApprovalStep from getStepBeingEvaluated is null
            final ApprovalStep approvalStep = approvalProfile.getStepBeingEvaluated(approvalsPerformed);
            if (lastApproval!=null && (!lastApproval.isApproved() || expired)) {
                if (log.isDebugEnabled()) {
                    log.debug("Creating rejected or expired notification for approval profile: "+approvalProfile.getProfileName());
                }
                if (approvalStep==null || approvalStep.getStepIdentifier()==lastApproval.getStepId()) {
                    // If the approval has been rejected or expired, we should notify all partition owners in the current step that still has not approved it
                    final int currentStepId = lastApproval.getStepId();
                    final ApprovalPartition currentApprovalPartition = approvalProfile.getStep(currentStepId).getPartition(lastApproval.getPartitionId());
                    if (expired) {
                        sendApprovalNotification(approvalRequest, approvalProfile, approvalData.getId(), currentStepId, currentApprovalPartition, ApprovalPartitionWorkflowState.EXPIRED, lastApproval);
                    } else {
                        sendApprovalNotification(approvalRequest, approvalProfile, approvalData.getId(), currentStepId, currentApprovalPartition, ApprovalPartitionWorkflowState.REJECTED, lastApproval);
                    }
                    if (approvalStep!=null) {
                        // Check which of the remaining partitions that need to be notified
                        for (final ApprovalPartition approvalPartition : approvalStep.getPartitions().values()) {
                            final int remainingApprovalsInPartition = approvalProfile.getRemainingApprovalsInPartition(approvalsPerformed, lastApproval.getStepId(), approvalPartition.getPartitionIdentifier());
                            if (remainingApprovalsInPartition>0) {
                                if (expired) {
                                    sendApprovalNotification(approvalRequest, approvalProfile, approvalData.getId(), currentStepId, approvalPartition, ApprovalPartitionWorkflowState.EXPIRED, lastApproval);
                                } else {
                                    sendApprovalNotification(approvalRequest, approvalProfile, approvalData.getId(), currentStepId, approvalPartition, ApprovalPartitionWorkflowState.REJECTED, lastApproval);
                                }
                            }
                        }
                    }
                } else {
                    if (log.isDebugEnabled()) {
                        log.debug("All steps have been satisfied, so no approvals sent for approval profile: "+approvalProfile.getProfileName());
                    }
                }
            } else {
                if (lastApproval!=null) {
                    if (log.isDebugEnabled()) {
                        log.debug("Request approved, notify every partition owner who's work flow is affected by the made approval for approval profile: "+approvalProfile.getProfileName());
                    }
                    // Notify every partition owner who's work flow is affected by the made approval
                    final int currentStepId = lastApproval.getStepId();
                    final int remainingApprovalsInPartition = approvalProfile.getRemainingApprovalsInPartition(approvalsPerformed, currentStepId, lastApproval.getPartitionId());
                    final ApprovalPartition currentApprovalPartition = approvalProfile.getStep(lastApproval.getStepId()).getPartition(lastApproval.getPartitionId());
                    if (remainingApprovalsInPartition>0) {
                        sendApprovalNotification(approvalRequest, approvalProfile, approvalData.getId(), currentStepId, currentApprovalPartition, ApprovalPartitionWorkflowState.APPROVED_PARTIALLY, lastApproval);
                    } else {
                        sendApprovalNotification(approvalRequest, approvalProfile, approvalData.getId(), currentStepId, currentApprovalPartition, ApprovalPartitionWorkflowState.APPROVED, lastApproval);
                    }
                }
                // If this is a new approval request or the current approval has completed a step, we should notify all partition owners in the next step
                if (lastApproval==null || (approvalStep!=null && approvalStep.getStepIdentifier()!=lastApproval.getStepId())) {
                    if (log.isDebugEnabled()) {
                        log.debug("This is a new approval request or the current approval has completed a step, we should notify all partition owners in the next step for approval profile: "+approvalProfile.getProfileName());
                    }
                    for (final ApprovalPartition approvalPartition : approvalStep.getPartitions().values()) {
                        sendApprovalNotification(approvalRequest, approvalProfile, approvalData.getId(), approvalStep.getStepIdentifier(), approvalPartition, ApprovalPartitionWorkflowState.REQUIRES_ACTION, lastApproval);
                    }
                }
            }
        } catch (AuthenticationFailedException e) {
            log.warn("Unexpected failure during approval notification. Already performed approval where no longer authorized to do so.");
        }
    }
    
    /** Send approval notification to the partition owner if it has notifications enabled. */
    private void sendApprovalNotification(final ApprovalRequest approvalRequest, final ApprovalProfile approvalProfile, final int requestId, final int approvalStepId, final ApprovalPartition approvalPartition,
            final ApprovalPartitionWorkflowState approvalPartitionWorkflowState, final Approval lastApproval) {
        
        if(!approvalProfile.isNotificationEnabled(approvalPartition) && !approvalProfile.isUserNotificationEnabled(approvalPartition)) {
            if (log.isDebugEnabled()) {
                String partitionString = "";
                if(approvalProfile instanceof PartitionedApprovalProfile) {
                    final DynamicUiProperty<? extends Serializable> partitionNameproperty = approvalPartition.getProperty(PartitionedApprovalProfile.PROPERTY_NAME);
                    final String partitionName;
                    if (partitionNameproperty != null) {
                        partitionName = partitionNameproperty.getValueAsString();
                    } else {
                        partitionName = "Noname with ID "+approvalPartition.getPartitionIdentifier();
                    }
                    partitionString = " for partition '"+partitionName + "'";
                }
                log.debug("Neither notifications nor user notifications are enabled"+ partitionString + " in approval profile: "+approvalProfile.getProfileName());
            }
            return;
        }
        
        final int partitionId = approvalPartition.getPartitionIdentifier();
        // There may be no partition name if it is not a partitioned approval
        final String partitionName;
        DynamicUiProperty<? extends Serializable> partNameProperty = approvalPartition.getProperty(PartitionedApprovalProfile.PROPERTY_NAME);
        if (partNameProperty != null) {
            partitionName = partNameProperty.getValueAsString();
        } else {
            partitionName = null;
        }
        final String approvalType = intres.getLocalizedMessage(ApprovalDataVO.APPROVALTYPENAMES[approvalRequest.getApprovalType()]);
        final String workflowState = intres.getLocalizedMessage("APPROVAL_WFSTATE_" + approvalPartitionWorkflowState.name());
        final String requestor = approvalRequest.getRequestAdmin().toString();
        final String lastApprovedBy;
        if (lastApproval != null) {
            if (lastApproval.getAdmin() != null) {
                lastApprovedBy = lastApproval.getAdmin().toString();
            } else {
                if (log.isDebugEnabled()) {
                    log.debug("lastApproval.getAdmin returned null for approvalId: "+requestId);
                }
                lastApprovedBy = "";
            }
        } else {
            lastApprovedBy = "";            
        }

        if(approvalProfile.isNotificationEnabled(approvalPartition)) {
            final String recipient = (String) approvalPartition.getProperty(ApprovalProfile.PROPERTY_NOTIFICATION_EMAIL_RECIPIENT).getValue();
            final String sender = (String) approvalPartition.getProperty(ApprovalProfile.PROPERTY_NOTIFICATION_EMAIL_SENDER).getValue();
            final String subject = (String) approvalPartition.getProperty(ApprovalProfile.PROPERTY_NOTIFICATION_EMAIL_MESSAGE_SUBJECT).getValue();
            final String body = ((MultiLineString)approvalPartition.getProperty(ApprovalProfile.PROPERTY_NOTIFICATION_EMAIL_MESSAGE_BODY).getValue()).getValue();
            final ApprovalNotificationParameterGenerator parameters = new ApprovalNotificationParameterGenerator(requestId, approvalStepId, partitionId, partitionName, approvalType, workflowState, requestor, lastApprovedBy);
            try {
                MailSender.sendMailOrThrow(sender, Arrays.asList(recipient.split(" ")), MailSender.NO_CC, parameters.interpolate(subject), parameters.interpolate(body), MailSender.NO_ATTACHMENTS);
                log.info(intres.getLocalizedMessage("approval.sentnotification", requestId));
            } catch (MailException e) {
                log.info(intres.getLocalizedMessage("approval.errornotification", requestId), e);
            }
        } else {
            if(log.isDebugEnabled()) {
                log.debug("Admin notifications are not enabled for approval profile: "+approvalProfile.getProfileName());
            }
        }
        
        if(approvalProfile.isUserNotificationEnabled(approvalPartition)) {
            final EndEntityInformation userdata = getEndEntity(approvalRequest);
            if ((userdata != null) && (userdata.getEmail() != null)) {
                final String userRecipient = userdata.getEmail();
                final String userSender = (String) approvalPartition.getProperty(ApprovalProfile.PROPERTY_USER_NOTIFICATION_EMAIL_SENDER).getValue();
                final String userSubject = (String) approvalPartition.getProperty(ApprovalProfile.PROPERTY_USER_NOTIFICATION_EMAIL_MESSAGE_SUBJECT).getValue();
                final String userBody = ((MultiLineString)approvalPartition.getProperty(ApprovalProfile.PROPERTY_USER_NOTIFICATION_EMAIL_MESSAGE_BODY).getValue()).getValue();
                final ApprovalNotificationParameterGenerator userParameters = new ApprovalNotificationParameterGenerator(requestId, approvalStepId, partitionId, partitionName, approvalType, workflowState, requestor, lastApprovedBy);
                try {
                    MailSender.sendMailOrThrow(userSender, Arrays.asList(userRecipient.split(" ")), MailSender.NO_CC, userParameters.interpolate(userSubject), userParameters.interpolate(userBody), MailSender.NO_ATTACHMENTS);
                    log.info(intres.getLocalizedMessage("approval.sentnotification", requestId));
                } catch (Exception e) {
                    log.info(intres.getLocalizedMessage("approval.errornotification", requestId), e);
                }
            } else {
                log.info(intres.getLocalizedMessage("approval.errornotification", requestId) + " No email was found in the end entity");
            }
        } else {
            if(log.isDebugEnabled()) {
                log.debug("User notifications are not enabled for approval profile: "+approvalProfile.getProfileName());
            }
        }
    }
    
    private EndEntityInformation getEndEntity(final ApprovalRequest approvalRequest) {
        if(approvalRequest instanceof AddEndEntityApprovalRequest) {
            return ((AddEndEntityApprovalRequest) approvalRequest).getEndEntityInformation();
        } else if(approvalRequest instanceof ChangeStatusEndEntityApprovalRequest) {
            //See legacy instantiation in EndEntityManagementSessionBean
            EndEntityInformation endEntityInformation = endEntityAccessSession
                    .findUser(((ChangeStatusEndEntityApprovalRequest) approvalRequest).getUsername());
            return endEntityInformation;
        } else if(approvalRequest instanceof EditEndEntityApprovalRequest) {
            //See legacy instantiation in EndEntityManagementSessionBean
            return ((EditEndEntityApprovalRequest) approvalRequest).getNewEndEntityInformation();
        } else if(approvalRequest instanceof RevocationApprovalRequest) {
            //See legacy instantiation in RevocationSessionBean
            EndEntityInformation endEntityInformation = endEntityAccessSession
                    .findUser(((RevocationApprovalRequest) approvalRequest).getUsername());
            return endEntityInformation;
        }
        
        return null;
    }

    private Integer findFreeApprovalId() {
        final ProfileID.DB db = new ProfileID.DB() {
            @Override
            public boolean isFree(int i) {
                return findByApprovalId(i).size() == 0;
            }
        };
        return Integer.valueOf( ProfileID.getNotUsedID(db) );
    }

    /**
     * Method used to mark an non-executable approval as done if the last step is performed will the status be set as expired.
     * 
     * @throws ApprovalRequestExpiredException if the step have already been executed
     */
    @SuppressWarnings("deprecation")
    private void markStepAsDone(final ApprovalData approvalData, final int step) throws ApprovalRequestExpiredException {
        final ApprovalRequest ar = approvalData.getApprovalRequest();
        if (!ar.isExecutable() && approvalData.getStatus() == ApprovalDataVO.STATUS_APPROVED) {
            if (!ar.isStepDone(step)) {
                ar.markStepAsDone(step);
                setApprovalRequest(approvalData, ar);
                if (step == ar.getNumberOfApprovalSteps() - 1) {
                    approvalData.setStatus(ApprovalDataVO.STATUS_EXPIRED);
                }
            } else {
                throw new ApprovalRequestExpiredException("Error step " + step + " of approval with id " + approvalData.getApprovalid()
                        + " have alread been performed");
            }
        }
    }

    /**
     * Method used by the requestadmin to check if an approval request have been approved
     * @param step the number of the step to check. 
     * @return 0 (ApprovalDataVO.STATUS_APROVED) if approved, the number of approvals left if still waiting for approval, otherwise the ApprovalDataVO.STATUS constants indicating the status.
     * @throws ApprovalRequestExpiredException if the request or approval have expired, the status will be EXPIREDANDNOTIFIED in this case.
     */
    @SuppressWarnings("deprecation")
    private int isApproved(final ApprovalData approvalData, final int step) throws ApprovalRequestExpiredException {
        if (approvalData.getApprovalRequest().isStepDone(step)) {
            return ApprovalDataVO.STATUS_EXPIRED;
        }
        if (approvalData.hasRequestOrApprovalExpired()) {
            if (approvalData.getStatus() != ApprovalDataVO.STATUS_EXPIREDANDNOTIFIED && approvalData.getStatus() != ApprovalDataVO.STATUS_EXECUTED
                    && approvalData.getStatus() != ApprovalDataVO.STATUS_EXECUTIONDENIED
                    && approvalData.getStatus() != ApprovalDataVO.STATUS_EXECUTIONFAILED) {
                approvalData.setStatus(ApprovalDataVO.STATUS_EXPIREDANDNOTIFIED);
                throw new ApprovalRequestExpiredException();
            }
            return ApprovalDataVO.STATUS_EXPIREDANDNOTIFIED;
        }
        if (approvalData.getStatus() == ApprovalDataVO.STATUS_WAITINGFORAPPROVAL) {
            return approvalData.getApprovalRequest().getApprovalProfile().getRemainingApprovals(approvalData.getApprovals());
        }
        return approvalData.getStatus();
    }
    
    @TransactionAttribute(TransactionAttributeType.REQUIRED)
    @Override
    public void updateApprovalRequest(final int approvalDataId, final ApprovalRequest approvalRequest) {
        ApprovalData approvalData = findById(approvalDataId);
        setApprovalRequest(approvalData, approvalRequest);
        entityManager.merge(approvalData);
    }
    
    private final void setApprovalRequest(final ApprovalData approvalData, final ApprovalRequest approvalRequest) {
        try {
            final ByteArrayOutputStream baos = new ByteArrayOutputStream();
            final ObjectOutputStream oos = new ObjectOutputStream(baos);
            oos.writeObject(approvalRequest);
            oos.flush();
            approvalData.setRequestdata(new String(Base64.encode(baos.toByteArray(), false)));
        } catch (IOException e) {
            log.error("Error building approval request.", e);
            throw new IllegalStateException(e);
        }
    }
    
    @Override
    public void setApprovals(ApprovalData approvalData, final Collection<Approval> approvals) {
        try {
            final ByteArrayOutputStream baos = new ByteArrayOutputStream();
            final ObjectOutputStream oos = new ObjectOutputStream(baos);
            final int size = approvals.size();
            oos.writeInt(size);
            final Iterator<Approval> iter = approvals.iterator();
            while (iter.hasNext()) {
                final Approval next = iter.next();
                oos.writeObject(next);
            }
            oos.flush();
            approvalData.setApprovaldata(new String(Base64.encode(baos.toByteArray(), false)));
        } catch (IOException e) {
            log.error("Error building approvals.", e);
            throw new IllegalStateException(e);
        }
    }
    
    @Override
    public void extendApprovalRequestNoAuth(final AuthenticationToken authenticationToken, final int approvalDataId, final long extendForMillisParam) {
        if (extendForMillisParam <= 0) {
            throw new IllegalArgumentException("Time to extend for must be a positive non-zero number: " + extendForMillisParam);
        }
        
        final ApprovalData approvalData = findById(approvalDataId);
        if (approvalData == null) {
            throw new IllegalStateException("Approval request with ID " + approvalDataId + " does not exist");
        }
        
        // Check status
        final long status = approvalData.getStatus();
        if (status != ApprovalDataVO.STATUS_EXPIRED &&
                status != ApprovalDataVO.STATUS_EXPIREDANDNOTIFIED &&
                status != ApprovalDataVO.STATUS_WAITINGFORAPPROVAL) {
            throw new IllegalStateException("Can't extend approval request in this state (" + status + ")");
        }
        
        // Check maximum extension time
        long maxExtend = getMaxExtensionTime(approvalData.getApprovalDataVO());
        if (maxExtend <= 0) {
            throw new IllegalStateException("Approval profile (or configured default value) does not allow request extension");
        }
        long extendForMillis = extendForMillisParam;
        if (extendForMillis > maxExtend) {
            log.info("Tried to extend approval request ID " + approvalData + " for " + extendForMillisParam + " ms, " +
                    "which is more than the maximum of the approval profile, " + maxExtend + " ms");
            extendForMillis = maxExtend;
        }
        
        approvalData.setExpiredate(new Date().getTime() + extendForMillis);
        approvalData.setStatus(ApprovalDataVO.STATUS_WAITINGFORAPPROVAL);
        entityManager.merge(approvalData);
        
        String msg = intres.getLocalizedMessage("approval.extended", approvalData.getId(), extendForMillis);
        final Map<String, Object> details = new LinkedHashMap<>();
        details.put("msg", msg);
        auditSession.log(EjbcaEventTypes.APPROVAL_EXTEND, EventStatus.SUCCESS, EjbcaModuleTypes.APPROVAL, EjbcaServiceTypes.EJBCA,
                authenticationToken.toString(), String.valueOf(approvalData.getCaid()), null, null, details);
    }
    
    private long getMaxExtensionTime(final ApprovalDataVO advo) {
        ApprovalProfile prof = advo.getApprovalProfile();
        if (prof != null) {
            final Integer approvalProfileId = advo.getApprovalProfile().getProfileId();
            prof = approvalProfileSession.getApprovalProfile(approvalProfileId);
            return prof.getMaxExtensionTime();
        }
        return EjbcaConfiguration.getApprovalDefaultMaxExtensionTime();
    }
       
    /** @return the found entity instance or null if the entity does not exist */
    private ApprovalData findById(final Integer id) {
        return entityManager.find(ApprovalData.class, id);
    }
    
    /** @return return the query results as a List. */
    private List<ApprovalData> findByApprovalId(final int approvalid) {
        final TypedQuery<ApprovalData> query = entityManager.createQuery("SELECT a FROM ApprovalData a WHERE a.approvalid=:approvalId",
                ApprovalData.class);
        query.setParameter("approvalId", approvalid);
        return query.getResultList();
    }
    
    /** @return return the query results as a List. */
    private List<ApprovalData> findByApprovalIdNonExpired(final int approvalid) {
        final TypedQuery<ApprovalData> query = entityManager.createQuery(
                "SELECT a FROM ApprovalData a WHERE a.approvalid=:approvalId AND (a.status>" + ApprovalDataVO.STATUS_EXPIRED + ")",
                ApprovalData.class);
        query.setParameter("approvalId", approvalid);
        return query.getResultList();
    }

    /** @return return the query results as a List<ApprovalData>. */
    private List<ApprovalData> findByCustomQuery(final int index, final int numberofrows, final String customQuery) {
        final List<ApprovalData> ret = new ArrayList<ApprovalData>();
        /* Hibernate on DB2 wont allow us to "SELECT *" in combination with setMaxResults.
         * Ingres wont let us access a LOB in a List using a native query for all fields.
         * -> So we will get a list of primary keys and the fetch the whole entities one by one...
         * 
         * As a sad little bonus, DB2 native queries returns a pair of {BigInteger, Integer}
         * where the first value is row and the second is the value.
         * As another sad little bonus, Oracle native queries returns a pair of {BigDecimal, BigDecimal}
         * where the first value is the value and the second is the row.
         */
        final javax.persistence.Query query = entityManager.createNativeQuery("SELECT id FROM ApprovalData WHERE " + customQuery);
        query.setFirstResult(index);
        query.setMaxResults(numberofrows);
        @SuppressWarnings("unchecked")
        final List<Object> ids = query.getResultList();
        for (Object object : ids) {
            final int id = ValueExtractor.extractIntValue(object);
            ret.add(entityManager.find(ApprovalData.class, id));
        }
        return ret;
    }

    @Override
    public int getIdFromApprovalId(int approvalId) {
        List<ApprovalData> ads = findByApprovalId(approvalId);
        if (ads.isEmpty()) {
            log.warn("There is no approval request with approval ID " + approvalId);
            return 0;
        }
        if (ads.size() > 1) {
            log.warn("There is more than one approval request with approval ID " + approvalId);
        }
        return ads.get(0).getId();
    }

    @Override
    public int getRemainingNumberOfApprovals(int requestId) throws ApprovalException, ApprovalRequestExpiredException {
        ApprovalData approvalData = findById(requestId);
        if (approvalData == null) {
            throw new ApprovalException("Approval with ID " + requestId + " not found.");
        }
        int result = approvalData.getApprovalRequest().getApprovalProfile().getRemainingApprovals(approvalData.getApprovals());
        if(result <= 0) {
            //If approval is done, or has been rejected
            return result;
        } else if (approvalData.hasRequestOrApprovalExpired()) {
            //If it's expired, toss an exception
            throw new ApprovalRequestExpiredException("Approval Request with request ID " + requestId + " has expired.");
        } else {
            //Otherwise just return the number of remaining approvals
            return result;
        }
    }
}
