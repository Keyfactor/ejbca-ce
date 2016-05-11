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
import java.security.cert.Certificate;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.Date;
import java.util.Iterator;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

import javax.ejb.EJB;
import javax.ejb.Stateless;
import javax.ejb.TransactionAttribute;
import javax.ejb.TransactionAttributeType;
import javax.persistence.EntityManager;
import javax.persistence.PersistenceContext;

import org.apache.commons.lang.StringUtils;
import org.apache.log4j.Logger;
import org.cesecore.ErrorCode;
import org.cesecore.audit.enums.EventStatus;
import org.cesecore.audit.log.SecurityEventsLoggerSessionLocal;
import org.cesecore.authentication.tokens.AuthenticationToken;
import org.cesecore.authentication.tokens.X509CertificateAuthenticationToken;
import org.cesecore.authorization.AuthorizationDeniedException;
import org.cesecore.authorization.control.AccessControlSessionLocal;
import org.cesecore.authorization.control.StandardRules;
import org.cesecore.certificates.certificate.CertificateStoreSessionLocal;
import org.cesecore.certificates.endentity.EndEntityInformation;
import org.cesecore.configuration.GlobalConfigurationSessionLocal;
import org.cesecore.jndi.JndiConstants;
import org.cesecore.roles.access.RoleAccessSessionLocal;
import org.cesecore.util.Base64;
import org.cesecore.util.CertTools;
import org.cesecore.util.ProfileID;
import org.ejbca.config.GlobalConfiguration;
import org.ejbca.core.ejb.audit.enums.EjbcaEventTypes;
import org.ejbca.core.ejb.audit.enums.EjbcaModuleTypes;
import org.ejbca.core.ejb.audit.enums.EjbcaServiceTypes;
import org.ejbca.core.ejb.ra.EndEntityAccessSessionLocal;
import org.ejbca.core.model.InternalEjbcaResources;
import org.ejbca.core.model.approval.AdminAlreadyApprovedRequestException;
import org.ejbca.core.model.approval.Approval;
import org.ejbca.core.model.approval.ApprovalDataUtil;
import org.ejbca.core.model.approval.ApprovalDataVO;
import org.ejbca.core.model.approval.ApprovalException;
import org.ejbca.core.model.approval.ApprovalNotificationParamGen;
import org.ejbca.core.model.approval.ApprovalProfile;
import org.ejbca.core.model.approval.ApprovalProfileNumberOfApprovals;
import org.ejbca.core.model.approval.ApprovalRequest;
import org.ejbca.core.model.approval.ApprovalRequestExpiredException;
import org.ejbca.core.model.approval.ApprovalStep;
import org.ejbca.core.model.authorization.AccessRulesConstants;
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

    @EJB
    private AccessControlSessionLocal authorizationSession;
    @EJB
    private RoleAccessSessionLocal roleAccessSession;
    @EJB
    private CertificateStoreSessionLocal certificateStoreSession;
    @EJB
    private SecurityEventsLoggerSessionLocal auditSession;
    @EJB
    private EndEntityAccessSessionLocal endEntityAccessSession;
    @EJB
    private GlobalConfigurationSessionLocal globalConfigurationSession;
    @EJB
    private ApprovalProfileSessionLocal approvalProfileSession;
    
    @Override
    public void addApprovalRequest(AuthenticationToken admin, ApprovalRequest approvalRequest) throws ApprovalException {
    	if (log.isTraceEnabled()) {
    		log.trace(">addApprovalRequest");
    	}
        int approvalId = approvalRequest.generateApprovalId();

        ApprovalDataVO data = findNonExpiredApprovalRequest(admin, approvalId);
        if (data != null) {
            String msg = intres.getLocalizedMessage("approval.alreadyexists", approvalId);
            log.info(msg);
            throw new ApprovalException(ErrorCode.APPROVAL_ALREADY_EXISTS, msg);
        } else {
            // There exists no approval request with status waiting. Add a new one
            try {
                final Integer freeId = findFreeApprovalId();
                final ApprovalData approvalData = new ApprovalData(freeId);
                approvalData.setApprovalid(approvalRequest.generateApprovalId());
                approvalData.setApprovaltype(approvalRequest.getApprovalType());
                final ApprovalProfile approvalProfile = approvalRequest.getApprovalProfile();
                approvalData.setApprovalProfileId(approvalProfileSession.getApprovalProfileId(approvalProfile.getProfileName()));
                approvalData.setEndentityprofileid(approvalRequest.getEndEntityProfileId());
                approvalData.setCaid(approvalRequest.getCAId());
                if (approvalRequest.getRequestAdminCert() != null) {
                    approvalData.setReqadmincertissuerdn(CertTools.getIssuerDN(approvalRequest.getRequestAdminCert()));
                    approvalData.setReqadmincertsn(CertTools.getSerialNumberAsString(approvalRequest.getRequestAdminCert()));
                }
                setApprovalRequest(approvalData, approvalRequest);
                setApprovals(approvalData, new ArrayList<Approval>());
                approvalData.setExpiredate((new Date()).getTime() + approvalRequest.getRequestValidity());
                approvalData.setRemainingapprovals(approvalRequest.getNumOfRequiredApprovals());
                entityManager.persist(approvalData);
                final GlobalConfiguration gc = (GlobalConfiguration) globalConfigurationSession.getCachedConfiguration(GlobalConfiguration.GLOBAL_CONFIGURATION_ID);
                if (gc.getUseApprovalNotifications()) {
                    sendApprovalNotification(admin, gc.getApprovalAdminEmailAddress(), gc.getApprovalNotificationFromAddress(), gc.getBaseUrl()
                            + "adminweb/approval/approveaction.jsf?uniqueId=" + freeId,
                            intres.getLocalizedMessage("notification.newrequest.subject"), intres.getLocalizedMessage("notification.newrequest.msg"),
                            freeId, approvalRequest.getNumOfRequiredApprovals(), new Date(), approvalRequest, null);
                }
                String msg = intres.getLocalizedMessage("approval.addedwaiting", approvalId);
                final Map<String, Object> details = new LinkedHashMap<String, Object>();
                details.put("msg", msg);
                auditSession.log(EjbcaEventTypes.APPROVAL_ADD, EventStatus.SUCCESS, EjbcaModuleTypes.APPROVAL, EjbcaServiceTypes.EJBCA,
                        admin.toString(), String.valueOf(approvalRequest.getCAId()), null, null, details);
            } catch (Exception e1) {
                String msg = intres.getLocalizedMessage("approval.erroradding", approvalId);
                log.error(msg, e1);
                final Map<String, Object> details = new LinkedHashMap<String, Object>();
                details.put("msg", msg);
                details.put("Error", e1.getMessage());
                auditSession.log(EjbcaEventTypes.APPROVAL_ADD, EventStatus.FAILURE, EjbcaModuleTypes.APPROVAL, EjbcaServiceTypes.EJBCA,
                        admin.toString(), String.valueOf(approvalRequest.getCAId()), null, null, details);
            }
        }
        if (log.isTraceEnabled()) {
        	log.trace("<addApprovalRequest");
        }
    }

    @Override
    public void removeApprovalRequest(AuthenticationToken admin, int id) throws ApprovalException {
        log.trace(">removeApprovalRequest");
        try {
            ApprovalData ad = ApprovalData.findById(entityManager, Integer.valueOf(id));
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
        log.trace("<removeApprovalRequest");
    }

    @Override
    public void reject(AuthenticationToken admin, int approvalId, Approval approval, final ApprovalStep approvalStep, final boolean isNrOfApprovalsProfile)
            throws ApprovalRequestExpiredException, AuthorizationDeniedException, ApprovalException, AdminAlreadyApprovedRequestException {
        log.trace(">reject");
        ApprovalData adl;
        try {
            adl = isAuthorizedBeforeApproveOrReject(admin, approvalId, approvalStep);
        } catch (ApprovalException e1) {
            String msg = intres.getLocalizedMessage("approval.notexist", approvalId);
            log.info(msg);
            throw e1;
        }

        checkExecutionPossibility(admin, adl);
        approval.setApprovalAdmin(false, admin);

        try {
            reject(adl, approval, approvalStep, isNrOfApprovalsProfile);
            final GlobalConfiguration gc = (GlobalConfiguration) globalConfigurationSession.getCachedConfiguration(GlobalConfiguration.GLOBAL_CONFIGURATION_ID);
            if (gc.getUseApprovalNotifications()) {
                final ApprovalDataVO approvalDataVO = getApprovalDataVO(adl);
                sendApprovalNotification(admin, gc.getApprovalAdminEmailAddress(), gc.getApprovalNotificationFromAddress(), gc.getBaseUrl()
                        + "adminweb/approval/approveaction.jsf?uniqueId=" + adl.getId(),
                        intres.getLocalizedMessage("notification.requestrejected.subject"),
                        intres.getLocalizedMessage("notification.requestrejected.msg"), adl.getId(), approvalDataVO.getRemainingApprovals(),
                        approvalDataVO.getRequestDate(), approvalDataVO.getApprovalRequest(), approval);
            }
            final String detailsMsg = intres.getLocalizedMessage("approval.rejected", approvalId);
            auditSession.log(EjbcaEventTypes.APPROVAL_REJECT, EventStatus.SUCCESS, EjbcaModuleTypes.APPROVAL, EjbcaServiceTypes.EJBCA,
                    admin.toString(), String.valueOf(adl.getCaid()), null, null, detailsMsg);
        } catch (ApprovalRequestExpiredException e) {
            String msg = intres.getLocalizedMessage("approval.expired", approvalId);
            log.info(msg);
            throw e;
        }
        log.trace("<reject");
    }

    @Override
    public void checkExecutionPossibility(AuthenticationToken admin, ApprovalData adl) throws AdminAlreadyApprovedRequestException {
        // Check that the approver's principals don't exist among the existing usernames.
        ApprovalDataVO data = getApprovalDataVO(adl);
        int approvalId = data.getApprovalId();
        // String username = admin.getUsername();
        if (data.getReqadmincertissuerdn() != null) {
            // Check that the approver isn't the same as requested the action.
            AuthenticationToken requester = getRequestAuthenticationToken(adl);
            if (admin.equals(requester)) {
                String msg = intres.getLocalizedMessage("approval.error.cannotapproveownrequest", approvalId);
                log.info(msg);
                throw new AdminAlreadyApprovedRequestException(msg);
            }
        }
        // Check that his admin has not approved this request before
        Collection<Approval> approvals = data.getApprovals();
        for (Approval next : approvals) {
            if (next.getAdmin().equals(admin)) {
                String msg = intres.getLocalizedMessage("approval.error.alreadyapproved", approvalId);
                log.info(msg);
                throw new AdminAlreadyApprovedRequestException(msg);
            }
        }
        
        // Check that his admin has not approved the old request before
        approvals = data.getApprovalRequest().getOldApprovals();
        for (Approval next : approvals) {
            if (next.getAdmin().equals(admin)) {
                String msg = intres.getLocalizedMessage("approval.error.alreadyapproved", approvalId);
                log.info(msg);
                throw new AdminAlreadyApprovedRequestException(msg);
            }
        }
    }

    @Override
    public ApprovalData isAuthorizedBeforeApproveOrReject(AuthenticationToken admin, int approvalId, final ApprovalStep approvalStep) throws ApprovalException,
            AuthorizationDeniedException {
        ApprovalData retval = findNonExpiredApprovalDataLocal(approvalId);
        if (retval != null) {
            ApprovalDataVO advo = getApprovalDataVO(retval);
            ApprovalProfile profile = advo.getApprovalRequest().getApprovalProfile();
            if(profile.getApprovalProfileType() instanceof ApprovalProfileNumberOfApprovals) {
                checkNrOfApprovalAuthorization(admin, retval);
            } else {
                if(!profile.getApprovalProfileType().isAdminAllowedToApproveStep(admin, approvalStep, profile)) {
                    throw new AuthorizationDeniedException("Administrator not authorized for step " + 
                                approvalStep.getStepId() + " from profile " + profile.getProfileName());
                }
            }
        } else {
            throw new ApprovalException(ErrorCode.APPROVAL_REQUEST_ID_NOT_EXIST, "Suitable approval with id : " + approvalId + " doesn't exist");
        }
        return retval;
    }
    
    // TODO find a better name for the method
    private void checkNrOfApprovalAuthorization(final AuthenticationToken admin, 
            final ApprovalData approvalData) throws AuthorizationDeniedException, ApprovalException {
            if (approvalData.getEndentityprofileid() == ApprovalDataVO.ANY_ENDENTITYPROFILE) {
                if (!authorizationSession.isAuthorized(admin, AccessRulesConstants.REGULAR_APPROVECAACTION)) {
                    final String msg = intres.getLocalizedMessage("authorization.notuathorizedtoresource",
                            AccessRulesConstants.REGULAR_APPROVECAACTION, null);
                    throw new AuthorizationDeniedException(msg);
                }
            } else {
                if (!authorizationSession.isAuthorized(admin, AccessRulesConstants.REGULAR_APPROVEENDENTITY)) {
                    final String msg = intres.getLocalizedMessage("authorization.notuathorizedtoresource",
                            AccessRulesConstants.REGULAR_APPROVEENDENTITY, null);
                    throw new AuthorizationDeniedException(msg);
                }
                GlobalConfiguration globalConfiguration = (GlobalConfiguration) globalConfigurationSession
                        .getCachedConfiguration(GlobalConfiguration.GLOBAL_CONFIGURATION_ID);
                if (globalConfiguration.getEnableEndEntityProfileLimitations()) {
                    if (!authorizationSession.isAuthorized(admin, AccessRulesConstants.ENDENTITYPROFILEPREFIX + approvalData.getEndentityprofileid()
                            + AccessRulesConstants.APPROVE_END_ENTITY)) {
                        final String msg = intres.getLocalizedMessage("authorization.notuathorizedtoresource",
                                AccessRulesConstants.ENDENTITYPROFILEPREFIX + approvalData.getEndentityprofileid() + AccessRulesConstants.APPROVE_END_ENTITY,
                                null);
                        throw new AuthorizationDeniedException(msg);
                    }
                }
            }
            if (approvalData.getCaid() != ApprovalDataVO.ANY_CA) {
                if (!authorizationSession.isAuthorized(admin, StandardRules.CAACCESS.resource() + approvalData.getCaid())) {
                    final String msg = intres.getLocalizedMessage("authorization.notuathorizedtoresource",
                            StandardRules.CAACCESS.resource() + approvalData.getCaid(), null);
                    throw new AuthorizationDeniedException(msg);
                }
            }
    }

    @Override
    public int isApproved(AuthenticationToken admin, int approvalId, int step) throws ApprovalException, ApprovalRequestExpiredException {
        if (log.isTraceEnabled()) {
            log.trace(">isApproved, approvalId: " + approvalId);
        }
        int retval = ApprovalDataVO.STATUS_EXPIREDANDNOTIFIED;
        Collection<ApprovalData> result = ApprovalData.findByApprovalId(entityManager, approvalId);
        if (result.size() == 0) {
            throw new ApprovalException(ErrorCode.APPROVAL_REQUEST_ID_NOT_EXIST, "Approval request with id : " + approvalId + " does not exist");
        }
        Iterator<ApprovalData> iter = result.iterator();
        while (iter.hasNext()) {
            ApprovalData adl = iter.next();
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
    public int isApproved(AuthenticationToken admin, int approvalId) throws ApprovalException, ApprovalRequestExpiredException {
        return isApproved(admin, approvalId, 0);
    }

    @Override
    public void markAsStepDone(AuthenticationToken admin, int approvalId, int step) throws ApprovalException, ApprovalRequestExpiredException {
        if (log.isTraceEnabled()) {
            log.trace(">markAsStepDone, approvalId: " + approvalId + ", step " + step);
        }
        Collection<ApprovalData> result = ApprovalData.findByApprovalId(entityManager, approvalId);
        Iterator<ApprovalData> iter = result.iterator();
        if (result.size() == 0) {
            throw new ApprovalException(ErrorCode.APPROVAL_REQUEST_ID_NOT_EXIST, "Approval request with id : " + approvalId + " does not exist");
        }
        while (iter.hasNext()) {
            ApprovalData adl = iter.next();
            markStepAsDone(adl, step);
        }
        log.trace("<markAsStepDone.");
    }

    @TransactionAttribute(TransactionAttributeType.SUPPORTS)
    @Override
    public ApprovalDataVO findNonExpiredApprovalRequest(AuthenticationToken admin, int approvalId) {
        ApprovalDataVO retval = null;
        ApprovalData data = findNonExpiredApprovalDataLocal(approvalId);
        if (data != null) {
            retval = getApprovalDataVO(data);
        }
        return retval;
    }

    private ApprovalData findNonExpiredApprovalDataLocal(int approvalId) {
        ApprovalData retval = null;
        Collection<ApprovalData> result = ApprovalData.findByApprovalIdNonExpired(entityManager, approvalId);
        if (log.isDebugEnabled()) {
        	log.debug("Found number of approvalIdNonExpired: " + result.size());
        }
        for (ApprovalData next : result) {
            ApprovalDataVO data = getApprovalDataVO(next);
            if (data.getStatus() == ApprovalDataVO.STATUS_WAITINGFORAPPROVAL || data.getStatus() == ApprovalDataVO.STATUS_APPROVED
                    || data.getStatus() == ApprovalDataVO.STATUS_REJECTED) {
                retval = next;
            }
        }
        return retval;
    }

    @TransactionAttribute(TransactionAttributeType.SUPPORTS)
    @Override
    public Collection<ApprovalDataVO> findApprovalDataVO(AuthenticationToken admin, int approvalId) {
        log.trace(">findApprovalDataVO");
        ArrayList<ApprovalDataVO> retval = new ArrayList<ApprovalDataVO>();
        Collection<ApprovalData> result = ApprovalData.findByApprovalId(entityManager, approvalId);
        for (ApprovalData adl : result) {
            retval.add(getApprovalDataVO(adl));
        }
        log.trace("<findApprovalDataVO");
        return retval;
    }

    @TransactionAttribute(TransactionAttributeType.SUPPORTS)
    @Override
    public List<ApprovalDataVO> query(AuthenticationToken admin, Query query, int index, int numberofrows, String caAuthorizationString,
            String endEntityProfileAuthorizationString, final String approvalProfileAuthorizationString) throws AuthorizationDeniedException, IllegalQueryException {
        log.trace(">query()");
        String customQuery = "";
        // Check if query is legal.
        if (query != null && !query.isLegalQuery()) {
            throw new IllegalQueryException();
        }
        if (query != null) {
            customQuery += query.getQueryString();
        }
        if (!caAuthorizationString.equals("") && query != null) {
            customQuery += " AND " + caAuthorizationString;
        } else {
            customQuery += caAuthorizationString;
        }
        if (StringUtils.isNotEmpty(endEntityProfileAuthorizationString)) {
            if (caAuthorizationString.equals("") && query == null) {
                customQuery += endEntityProfileAuthorizationString;
            } else {
                customQuery += " AND " + endEntityProfileAuthorizationString;
            }
        }
        
        if (StringUtils.isNotEmpty(approvalProfileAuthorizationString)) {
            if (StringUtils.isEmpty(customQuery)) {
                customQuery += approvalProfileAuthorizationString;
            } else {
                customQuery += " AND " + approvalProfileAuthorizationString;
            }
        }
        
        final List<ApprovalData> approvalDataList = ApprovalData.findByCustomQuery(entityManager, index, numberofrows, customQuery);
        final List<ApprovalDataVO> returnData = new ArrayList<ApprovalDataVO>(approvalDataList.size());
        for (ApprovalData approvalData : approvalDataList) {
            final ApprovalDataVO advo = getApprovalDataVO(approvalData);
            final ApprovalStep approvalStep = advo.getApprovalRequest().getNextUnhandledApprovalStepByAdmin(admin);
            if(approvalStep != null) {
                returnData.add(advo);
            }
        }
        log.trace("<query()");
        return returnData;
    }

    @Override
    public void sendApprovalNotification(AuthenticationToken admin, String approvalAdminsEmail,
            String approvalNotificationFromAddress, String approvalURL, String notificationSubject, String notificationMsg, Integer id,
            int numberOfApprovalsLeft, Date requestDate, ApprovalRequest approvalRequest, Approval approval) {
        if (log.isTraceEnabled()) {
            log.trace(">sendNotification approval notification: id=" + id);
        }
        try {
            AuthenticationToken sendAdmin = admin;
            Certificate requestAdminCert = approvalRequest.getRequestAdminCert();
            String requestAdminDN = null;
            String requestAdminUsername = null;
            if (requestAdminCert != null) {
                requestAdminDN = CertTools.getSubjectDN(requestAdminCert);
                // Try to get username from database
                requestAdminUsername = certificateStoreSession.findUsernameByIssuerDnAndSerialNumber(CertTools.getIssuerDN(requestAdminCert),
                        CertTools.getSerialNumber(requestAdminCert));
            } else {
                requestAdminUsername = intres.getLocalizedMessage("CLITOOL");
                requestAdminDN = "CN=" + requestAdminUsername;
            }

            if (approvalAdminsEmail.equals("") || approvalNotificationFromAddress.equals("")) {
                final String msg = intres.getLocalizedMessage("approval.errornotificationemail", id);
                log.info(msg);
            } else {
                String approvalTypeText = intres.getLocalizedMessage(ApprovalDataVO.APPROVALTYPENAMES[approvalRequest.getApprovalType()]);

                String approvalAdminUsername = null;
                String approvalAdminDN = null;
                String approveComment = null;
                if (approval != null) {
                	// Do we have an approval admin certificate?
                	if (approval.getAdmin() instanceof X509CertificateAuthenticationToken) {
						X509CertificateAuthenticationToken xtoken = (X509CertificateAuthenticationToken) approval.getAdmin();
	                    approvalAdminDN = CertTools.getSubjectDN(xtoken.getCertificate());
	                    // Try to get username from database
	                    approvalAdminUsername = certificateStoreSession.findUsernameByIssuerDnAndSerialNumber(CertTools.getIssuerDN(xtoken.getCertificate()),
	                            CertTools.getSerialNumber(xtoken.getCertificate()));				
					} else {
	                    approvalAdminUsername = approval.getAdmin().toString();						
					}
                    approveComment = approval.getComment();
                }
                Integer numAppr = Integer.valueOf(numberOfApprovalsLeft);
                ApprovalNotificationParamGen paramGen = new ApprovalNotificationParamGen(requestDate, id, approvalTypeText, numAppr, approvalURL,
                        approveComment, requestAdminUsername, requestAdminDN, approvalAdminUsername, approvalAdminDN);
                String subject = paramGen.interpolate(notificationSubject);
                String message = paramGen.interpolate(notificationMsg);
                List<String> toList = Arrays.asList(approvalAdminsEmail);
                String sendAdminEmail = null;
            	if (sendAdmin instanceof X509CertificateAuthenticationToken) {
                    // Firstly, see if it exists in the certificate
					X509CertificateAuthenticationToken xtoken = (X509CertificateAuthenticationToken) sendAdmin;
                    // Try to get username from database
	                sendAdminEmail = CertTools.getEMailAddress(xtoken.getCertificate());
	                if (sendAdminEmail == null) {
	                    // Secondly, see if it exists locally
                        Certificate certificate = xtoken.getCertificate();
                        String username = certificateStoreSession.findUsernameByIssuerDnAndSerialNumber(CertTools.getIssuerDN(certificate),
                                CertTools.getSerialNumber(certificate));
                        EndEntityInformation endEntityInformation = endEntityAccessSession.findUser(admin, username);
                        if (endEntityInformation != null) {
                            sendAdminEmail = endEntityInformation.getEmail();
	                    }
	                }
				}
                if (sendAdminEmail == null || sendAdminEmail.length() == 0) {
                    final String msg = intres.getLocalizedMessage("approval.errornotificationemail", id);
                    log.info(msg);
                } else {
                    toList = Arrays.asList(approvalAdminsEmail, sendAdminEmail);
                }
                MailSender.sendMailOrThrow(approvalNotificationFromAddress, toList, MailSender.NO_CC, subject, message, MailSender.NO_ATTACHMENTS);
                final String msg = intres.getLocalizedMessage("approval.sentnotification", id);
                log.info(msg);
            }
        } catch (Exception e) {
            final String msg = intres.getLocalizedMessage("approval.errornotification", id);
            log.info(msg, e);
        }
        if (log.isTraceEnabled()) {
            log.trace("<sendNotification approval notification: id=" + id);
        }
    }

    private Integer findFreeApprovalId() {
        final ProfileID.DB db = new ProfileID.DB() {
            @Override
            public boolean isFree(int i) {
                return ApprovalData.findByApprovalId(ApprovalSessionBean.this.entityManager, i).size()==0;
            }
        };
        return Integer.valueOf( ProfileID.getNotUsedID(db) );
    }

    /**
     * Method that rejects an approval. After someone have rejected the request no-one else can approve it
     */
    private void reject(final ApprovalData approvalData, final Approval approval, final ApprovalStep approvalStep, 
            final boolean isNrOfApprovalProfile) throws ApprovalRequestExpiredException, ApprovalException {
        if (approvalData.hasRequestOrApprovalExpired()) {
            throw new ApprovalRequestExpiredException();
        }
        if (approvalData.getStatus() != ApprovalDataVO.STATUS_WAITINGFORAPPROVAL) {
            throw new ApprovalException("Wrong status of approval request.");
        }
        if(isNrOfApprovalProfile) {
            final int numberofapprovalsleft = approvalData.getRemainingapprovals() - 1;
            if (numberofapprovalsleft < 0) {
                throw new ApprovalException("Error already enough approvals have been done on this request.");
            }
            approvalData.setRemainingapprovals(0);
        } else {
            addApprovalToApprovalStep(approvalData, approvalStep, false);
        }
        final Collection<Approval> approvals = getApprovals(approvalData);
        approvals.add(approval);
        setApprovals(approvalData, approvals);
        if (getApprovalRequest(approvalData).isExecutable()) {
            approvalData.setStatus(ApprovalDataVO.STATUS_EXECUTIONDENIED);
            approvalData.setExpireDate(new Date());
        } else {
            approvalData.setStatus(ApprovalDataVO.STATUS_REJECTED);
            approvalData.setExpiredate((new Date()).getTime() + getApprovalRequest(approvalData).getApprovalValidity());
        }
    }

    /**
     * Method used to mark an non-executable approval as done if the last step is performed will the status be set as expired.
     * 
     * @throws ApprovalRequestExpiredException if the step have already been executed
     */
    private void markStepAsDone(final ApprovalData approvalData, final int step) throws ApprovalRequestExpiredException {
        final ApprovalRequest ar = getApprovalRequest(approvalData);
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
     * 
     * @return the number of approvals left, 0 if approved othervis is the ApprovalDataVO.STATUS constants returned indicating the statys.
     * @throws ApprovalRequestExpiredException if the request or approval have expired, the status will be EXPIREDANDNOTIFIED in this case.
     */
    private int isApproved(final ApprovalData approvalData, final int step) throws ApprovalRequestExpiredException {
        if (getApprovalRequest(approvalData).isStepDone(step)) {
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
            return approvalData.getRemainingapprovals();
        }
        return approvalData.getStatus();
    }

    /**
     * Method that returns the approval data. This method currently extracts the ApprovalRequest object.
     */
    private AuthenticationToken getRequestAuthenticationToken(final ApprovalData approvalData) {
        return getApprovalRequest(approvalData).getRequestAdmin();
    }

    @Override
    public ApprovalRequest getApprovalRequest(final ApprovalData approvalData) {
        return ApprovalDataUtil.getApprovalRequest(approvalData.getRequestdata());
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
            throw new RuntimeException(e);
        }
    }

    @Override
    public ApprovalDataVO getApprovalDataVO(ApprovalData approvalData) {
        approvalData.hasRequestOrApprovalExpired();
        return new ApprovalDataVO(approvalData.getId(), approvalData.getApprovalid(), approvalData.getApprovaltype(),
                approvalData.getEndentityprofileid(), approvalData.getCaid(), approvalData.getReqadmincertissuerdn(),
                approvalData.getReqadmincertsn(), approvalData.getStatus(), getApprovals(approvalData), getApprovalRequest(approvalData),
                approvalData.getRequestDate(), approvalData.getExpireDate(), approvalData.getRemainingapprovals());
    }

    @Override
    public Collection<Approval> getApprovals(ApprovalData approvalData) {
        return ApprovalDataUtil.getApprovals(approvalData.getApprovaldata());
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
            throw new RuntimeException(e);
        }
    }
    
    @Override
    public void addApprovalToApprovalStep(final ApprovalData approvalData, final ApprovalStep approvalStep, final boolean approved) throws ApprovalException {
        final ApprovalRequest approvalRequest = getApprovalRequest(approvalData);
        approvalRequest.updateApprovalStepMetadata(approvalStep.getStepId(), approvalStep.getMetadata());
        approvalRequest.addApprovalToStep(approvalStep.getStepId(), approved);
        setApprovalRequest(approvalData, approvalRequest);
    }
}
