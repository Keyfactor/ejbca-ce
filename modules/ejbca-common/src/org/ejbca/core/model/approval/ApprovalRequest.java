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
package org.ejbca.core.model.approval;

import java.io.ByteArrayInputStream;
import java.io.Externalizable;
import java.io.IOException;
import java.io.ObjectInput;
import java.io.ObjectOutput;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Collection;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

import javax.security.auth.x500.X500Principal;

import org.apache.log4j.Logger;
import org.cesecore.authentication.tokens.AlwaysAllowLocalAuthenticationToken;
import org.cesecore.authentication.tokens.AuthenticationToken;
import org.cesecore.authentication.tokens.LocalJvmOnlyAuthenticationToken;
import org.cesecore.authentication.tokens.UsernamePrincipal;
import org.cesecore.authentication.tokens.X509CertificateAuthenticationToken;
import org.cesecore.authorization.AuthorizationDeniedException;
import org.cesecore.util.Base64;
import org.cesecore.util.CertTools;
import org.ejbca.config.EjbcaConfiguration;
import org.ejbca.core.ejb.authentication.cli.CliAuthenticationToken;
import org.ejbca.core.ejb.authentication.cli.CliAuthenticationTokenReferenceRegistry;
import org.ejbca.core.model.approval.type.AccumulativeApprovalProfile;
import org.ejbca.core.model.log.Admin;

/**
 * Abstract Base class representing one approval request created when an administrator performs an action that requires an approval.
 * 
 * Contains information like: Admin that performs the request Data necessary to display the request to the approver Eventual data necessary to execute
 * the request.
 * 
 * @version $Id$
 */ 
// Suppressing deprecation due to backwards compatibility
@SuppressWarnings("deprecation")
public abstract class ApprovalRequest implements Externalizable {

    private static final long serialVersionUID = -1L;
    private static final Logger log = Logger.getLogger(ApprovalRequest.class);
    private static final int LATEST_BASE_VERSION = 5;

    /**
     * Constants indicating approval settings for viewing hard token through WS
     */
    public static final int REQ_APPROVAL_VIEW_HARD_TOKEN = 5;

    /**
     * Constants indicating approval settings for generating token certificate through WS
     */
    public static final int REQ_APPROVAL_GENERATE_TOKEN_CERTIFICATE = 6;
    
    /**
     * Simple request type means that the approver will only see new data about the action and will not compare it to old data
     */
    public static final int REQUESTTYPE_SIMPLE = 1;

    /**
     * Comparing request type means that the approving administrator have to compare old data with new data in the request.
     * 
     */
    public static final int REQUESTTYPE_COMPARING = 2;

    private AuthenticationToken requestAdmin = null; // Base64 encoding of x509certificate?
    private String requestSignature = null;
    private int approvalRequestType = REQUESTTYPE_SIMPLE;
    private int numOfRequiredApprovals = 0;
    private int cAId = 0;
    private int endEntityProfileId = 0;
    private boolean[] approvalStepsNrOfApprovals = { false };
    
    private ApprovalProfile approvalProfile;
    private ApprovalProfile secondApprovalProfile;
    private Map<Integer, ApprovalStep> approvalSteps;
    private Map<Integer, Boolean> approvalStepsHandledMap;
    
    private Collection<Approval> oldApprovals;
    /**
     * Main constructor of an approval request for standard one step approval request.
     * 
     * @param requestAdminCert the certificate of the requesting admin
     * @param requestSignature signature of the requester (OPTIONAL, for future use)
     * @param approvalRequestType one of TYPE_ constants
     * @param numOfRequiredApprovals
     * @param cAId the related cAId of the request that the approver must be authorized to or ApprovalDataVO.ANY_CA in applicable to any ca
     * @param endEntityProfileId the related profile id that the approver must be authorized to or ApprovalDataVO.ANY_ENDENTITYPROFILE if applicable
     *            to any end entity profile
     */
    protected ApprovalRequest(AuthenticationToken requestAdmin, String requestSignature, int approvalRequestType,
            int numOfRequiredApprovals, int cAId, int endEntityProfileId, ApprovalProfile firstApprovalProfile, 
            ApprovalProfile secondApprovalProfile) {
        super();
        setRequestAdmin(requestAdmin);
        this.requestSignature = requestSignature;
        this.approvalRequestType = approvalRequestType;
        this.cAId = cAId;
        this.endEntityProfileId = endEntityProfileId;

        this.approvalProfile = firstApprovalProfile;
        this.secondApprovalProfile = secondApprovalProfile;
        this.numOfRequiredApprovals = 0;
        if(this.approvalProfile != null) {
            initApprovalSteps();
        
            if(this.approvalProfile.getApprovalProfileType() instanceof AccumulativeApprovalProfile) {
                this.numOfRequiredApprovals = this.approvalProfile.getNumberOfApprovals();
            }
        }
        this.oldApprovals = new ArrayList<Approval>();
    }

    /**
     * Main constructor of an approval request.
     * 
     * @param requestAdminCert the certificate of the requesting admin
     * @param requestSignature signature of the requester (OPTIONAL, for future use)
     * @param approvalRequestType one of TYPE_ constants
     * @param numOfRequiredApprovals
     * @param cAId the related cAId of the request that the approver must be authorized to or ApprovalDataVO.ANY_CA in applicable to any ca
     * @param endEntityProfileId the related profile id that the approver must be authorized to or ApprovalDataVO.ANY_ENDENTITYPROFILE if applicable
     *            to any end entity profile
     * @param numberOfSteps that this type approval request supports.
     */
    protected ApprovalRequest(AuthenticationToken requestAdmin, String requestSignature, int approvalRequestType,
            int numOfRequiredApprovals, int cAId, int endEntityProfileId, int numberOfSteps, ApprovalProfile firstApprovalProfile, 
            ApprovalProfile secondApprovalProfile) {
        super();
        setRequestAdmin(requestAdmin);
        this.requestSignature = requestSignature;
        this.approvalRequestType = approvalRequestType;
        this.cAId = cAId;
        this.endEntityProfileId = endEntityProfileId;
        
        this.approvalProfile = firstApprovalProfile;
        this.secondApprovalProfile = secondApprovalProfile;
        this.numOfRequiredApprovals = 0;
        this.approvalStepsNrOfApprovals = new boolean[0];
        
        if(this.approvalProfile != null) {
            initApprovalSteps();
        
            if(this.approvalProfile.getApprovalProfileType() instanceof AccumulativeApprovalProfile) {
                this.numOfRequiredApprovals = this.approvalProfile.getNumberOfApprovals();
                this.approvalStepsNrOfApprovals = new boolean[numberOfSteps];
                for (int i = 0; i < numberOfSteps; i++) {
                    this.approvalStepsNrOfApprovals[i] = false;
                }
            }
        }
        this.oldApprovals = new ArrayList<Approval>();
    }

    /** Constuctor used in externaliziation only */
    public ApprovalRequest() {
    }
    
    private void initApprovalSteps() {
        approvalSteps = new HashMap<Integer, ApprovalStep>();
        approvalStepsHandledMap = new HashMap<Integer, Boolean>();
            
        if(approvalProfile.getApprovalProfileType() instanceof AccumulativeApprovalProfile) {
            final int requiredNrOfApprovals = approvalProfile.getNumberOfApprovals();
            for(int i=0; i<requiredNrOfApprovals; i++) {
                ApprovalStep step = new ApprovalStep(approvalProfile.getNewStepId(), null, new ArrayList<ApprovalStepMetadata>(), 1, false, null, new ArrayList<Integer>());
                approvalSteps.put(Integer.valueOf(step.getStepId()), step);
                approvalStepsHandledMap.put(Integer.valueOf(step.getStepId()), Boolean.valueOf(false));
            }
                
        } else {
            Map<Integer, ApprovalStep> steps = approvalProfile.getApprovalSteps();
            for(ApprovalStep step : steps.values()) {
                approvalSteps.put(Integer.valueOf(step.getStepId()), step);
                approvalStepsHandledMap.put(Integer.valueOf(step.getStepId()), Boolean.FALSE);
            }
        }
    }
    
    public Collection<Approval> getOldApprovals() {
        return oldApprovals;
    }
    
    public void setOldApprovals(final Collection<Approval> approvals) {
        oldApprovals = approvals;
    }
    
    /**   
     * The different approval parts. Could either be already approved or not approved yet
     */
    public Map<Integer, ApprovalStep> getApprovalSteps() {
        return approvalSteps;
    }
    public ApprovalStep getApprovalStep(final int stepId) {
        return approvalSteps.get(Integer.valueOf(stepId));
    }
    public void addApprovalToStep(final int stepId, final boolean approved) throws ApprovalException {
        ApprovalStep step = approvalSteps.get(stepId);
        step.addApproval(approved);
        approvalSteps.put(stepId, step);
        if(step.getApprovalStatus()==ApprovalDataVO.STATUS_APPROVED) {
            approvalStepsHandledMap.put(stepId, Boolean.TRUE);
        }
    }
    public void updateApprovalStepMetadata(final int stepId, final Collection<ApprovalStepMetadata> metadata) {
        for(ApprovalStepMetadata md : metadata) {
            updateOneApprovalStepMetadata(stepId, md);
        }
    }
    public void updateOneApprovalStepMetadata(final int stepId, final ApprovalStepMetadata metadata) {
        ApprovalStep step = approvalSteps.get(stepId);
        step.updateOneMetadata(metadata);
        approvalSteps.put(stepId, step);
    }
    public void updateOneApprovalStepMetadata(final int stepId, final int metadataId, final String optionValue, 
            final String optionNote) {
        ApprovalStep step = approvalSteps.get(stepId);
        step.updateOneMetadataValue(metadataId, optionValue, optionNote);
        approvalSteps.put(stepId, step);
    }
    public boolean areAllStepsApproved() {
        for(Boolean approved : approvalStepsHandledMap.values()) {
            if(!approved.booleanValue()) {
                return false;
            }
        }
        return true;
    }
    
    public ApprovalStep getNextUnhandledApprovalStepByAdmin(AuthenticationToken admin) {
        if (approvalSteps != null) {
            for (ApprovalStep step : approvalSteps.values()) {
                if (!approvalStepsHandledMap.get(step.getStepId()).booleanValue()) {
                    boolean isNextStep = true;
                    for (Integer dependStepId : step.getPreviousStepsDependency()) {
                        if (!approvalStepsHandledMap.get(dependStepId).booleanValue()) {
                            isNextStep = false;
                            break;
                        }
                    }
                    if (isNextStep) {
                        try {
                            if (approvalProfile.getApprovalProfileType().isAdminAllowedToApproveStep(admin, step, approvalProfile)) {
                                return step;
                            }
                        } catch (AuthorizationDeniedException e) {
                        }
                    }
                }
            }
        }
        return null;
    }
    
    public List<ApprovalStep> getApprovedApprovalSteps() {
        ArrayList<ApprovalStep> approvedSteps = new ArrayList<ApprovalStep>();
        for(Integer stepId : approvalSteps.keySet()) {
            if(approvalStepsHandledMap.get(stepId)) {
                ApprovalStep step = approvalSteps.get(stepId);
                if(step.getApprovalStatus()==ApprovalDataVO.STATUS_APPROVED) {
                    approvedSteps.add(step);
                }
            }
        }
        return approvedSteps;
    }
    
    
    /**
     * Returns a copy of this request as a new request to be approved according to the second 
     * approval profile
     * 
     * @return a copy of this request with the second approval profile as the primary approval profile
     */
    public abstract ApprovalRequest getRequestCloneForSecondApprovalProfile(Collection<Approval> oldApprovals);

    /**
     * Should return true if the request if of the type that should be executed by the last approver.
     * 
     * False if the request admin should do a polling action to try again.
     */
    public abstract boolean isExecutable();

    /**
     * A main function of the ApprovalRequest, the execute() method is run when all required approvals have been made.
     * 
     * execute should perform the action or nothing if the requesting admin is supposed to try his action again.
     */
    public abstract void execute() throws ApprovalRequestExecutionException;

    /**
     * Method that should generate an approval id for this type of approval, the same request i.e the same admin want's to do the same thing twice
     * should result in the same approvalId.
     */
    public abstract int generateApprovalId();

    /**
     * This method should return the request data in text representation. This text is presented for the approving administrator in order for him to
     * make a decision about the request. The AddEndEntityApprovalRequest and EditEndEntityApprovalRequest classes have a more detailed overloaded version,
     * that performs database queries to fill in the CA and profile names, etc. 
     * 
     * Should return a List of ApprovalDataText, one for each row
     */
    public abstract List<ApprovalDataText> getNewRequestDataAsText(AuthenticationToken admin);

    /**
     * This method should return the original request data in text representation. Should only be implemented by TYPE_COMPARING ApprovalRequests.
     * TYPE_SIMPLE requests should return null;
     * 
     * This text is presented for the approving administrator for him to compare of what will be done.
     * 
     * Should return a List of ApprovalDataText, one for each row
     */
    public abstract List<ApprovalDataText> getOldRequestDataAsText(AuthenticationToken admin);

    /**
     * This method is used to check if this is an allowed transition between two states, so that it does not require approval. Override this method to
     * add allowed transitions.
     * 
     * @return true if this transition does not require approval, false by default.
     * 
     */
    public boolean isAllowedTransition() {
        return false;
    }

    /**
     * Should return the time in millisecond that the request should be valid or Long.MAX_VALUE if it should never expire
     * 
     * Default if will return the value defined in the ejbca.properties
     */
    public long getRequestValidity() {
        return EjbcaConfiguration.getApprovalDefaultRequestValidity();
    }

    /**
     * Should return the time in millisecond that the approval should be valid or Long.MAX_VALUE if it should never expire
     * 
     * Default if will return the value defined in the ejbca.properties
     */
    public long getApprovalValidity() {
        return EjbcaConfiguration.getApprovalDefaultApprovalValidity();
    }

    /**
     * Should return one of the ApprovalDataVO.APPROVALTYPE_ constants
     */
    public abstract int getApprovalType();

    /**
     * Method returning the number of required approvals in order to execute the request.
     */
    public int getNumOfRequiredApprovals() {
        return numOfRequiredApprovals;
    }

    
    public ApprovalProfile getApprovalProfile() {
        return approvalProfile;
    }
    
    public ApprovalProfile getSecondApprovalProfile() {
        return secondApprovalProfile;
    }
    
    /**
     * The type of request type, one of TYPE_ constants
     * 
     */
    public int getApprovalRequestType() {
        return approvalRequestType;
    }

    /**
     * @return Returns the requestSignature. OPTIONAL
     */
    public String getRequestSignature() {
        return requestSignature;
    }

    /**
     * Returns the related ca id. The approving administrator must be authorized to this ca in order to approve it.
     */
    public int getCAId() {
        return cAId;
    }

    /**
     * Returns the related end entity profile id. The approving administrator must be authorized to this profile in order to approve it.
     */
    public int getEndEntityProfileId() {
        return endEntityProfileId;
    }

    /**
     * NOTE: This method should never be used publicly except from UpgradeSessionBean
     */
    public void setRequestAdmin(AuthenticationToken requestAdmin) {
        this.requestAdmin = requestAdmin;
    }

    /**
     * Returns the certificate of the request admin, if there is any. 
     * Walks through credentials of the request admins AuthenticationToken and returns the first certifciate encountered.
     * @return returns Certificate or null
     */
    public Certificate getRequestAdminCert() {
    	Set<?> credentials = requestAdmin.getCredentials();
    	if (credentials != null) {
        	for (Object credential : credentials) {
        		if (credential instanceof Certificate) {
    				return (Certificate) credential;
    			}
        	}    		
    	}
        return null;
    }

    public AuthenticationToken getRequestAdmin() {
        return requestAdmin;
    }

    /**
     * Returns true if this step have been executed before.
     * 
     * @param step to query
     */
    public boolean isStepDone(int step) {
        return approvalStepsNrOfApprovals[step];
    }

    /**
     * Marks the given step as done.
     * 
     * @param step to query
     */
    public void markStepAsDone(int step) {
        approvalStepsNrOfApprovals[step] = true;
    }

    /**
     * Returns the number of steps that this approval request supports.
     */
    public int getNumberOfApprovalSteps() {
        return approvalStepsNrOfApprovals.length;
    }

    public void writeExternal(ObjectOutput out) throws IOException {
        out.writeInt(LATEST_BASE_VERSION);
        out.writeObject(this.requestAdmin);
        out.writeObject(this.requestSignature);
        out.writeInt(this.approvalRequestType);
        out.writeInt(this.numOfRequiredApprovals);
        out.writeInt(this.cAId);
        out.writeInt(this.endEntityProfileId);
        out.writeInt(this.approvalStepsNrOfApprovals.length);
        for (int i = 0; i < approvalStepsNrOfApprovals.length; i++) {
            out.writeBoolean(approvalStepsNrOfApprovals[i]);
        }
        
        out.writeObject(approvalProfile);
        final boolean existSecondApprovalProfile = (secondApprovalProfile!=null); 
        out.writeBoolean(existSecondApprovalProfile);
        if(existSecondApprovalProfile) {
            out.writeObject(secondApprovalProfile);
        }
        
        out.writeInt(this.approvalSteps.size());
        for (Integer stepId : approvalSteps.keySet()) {
            out.writeObject(stepId);
            out.writeObject(approvalSteps.get(stepId));
        }
        
        out.writeInt(this.approvalStepsHandledMap.size());
        for (Integer stepId : approvalStepsHandledMap.keySet()) {
            out.writeObject(stepId);
            out.writeBoolean(approvalStepsHandledMap.get(stepId));
        }
        
        out.writeInt(this.oldApprovals.size());
        for (Approval approval : oldApprovals) {
            out.writeObject(approval);
        }
    }

    public void readExternal(ObjectInput in) throws IOException, ClassNotFoundException {
        final int version = in.readInt();
        if (version == 1) {
            final String requestAdminCert = (String) in.readObject();
            final byte[] certbuf = Base64.decode(requestAdminCert.getBytes());
            final CertificateFactory cf = CertTools.getCertificateFactory();
            X509Certificate x509cert = null;
            try {
                x509cert = (X509Certificate) cf.generateCertificate(new ByteArrayInputStream(certbuf));
            } catch (CertificateException e) {
                log.error(e);
            }
            this.requestAdmin = new X509CertificateAuthenticationToken(x509cert);
            this.requestSignature = (String) in.readObject();
            this.approvalRequestType = in.readInt();
            this.numOfRequiredApprovals = in.readInt();
            this.cAId = in.readInt();
            this.endEntityProfileId = in.readInt();
            this.approvalStepsNrOfApprovals = new boolean[1];
        }
        if (version == 2) {
            final Admin admin = (Admin) in.readObject();
            final X509Certificate x509cert = (X509Certificate)admin.getAdminInformation().getX509Certificate();
            AuthenticationToken token = null;
            if (x509cert == null) {
            	if (admin.getAdminInformation().isSpecialUser() && (admin.getUsername() != null)) {
            		token = new AlwaysAllowLocalAuthenticationToken(new UsernamePrincipal(admin.getUsername()));
            	}
            } else {
                token = new X509CertificateAuthenticationToken(x509cert);
            }
            this.requestAdmin = token;
            this.requestAdmin = null;
            this.requestSignature = (String) in.readObject();
            this.approvalRequestType = in.readInt();
            this.numOfRequiredApprovals = in.readInt();
            this.cAId = in.readInt();
            this.endEntityProfileId = in.readInt();
            this.approvalStepsNrOfApprovals = new boolean[1];
        }
        if (version == 3) {
        	// Version 2 and 3 only care about the certificate from the old Admin object
            final Admin admin = (Admin) in.readObject();
            final X509Certificate x509cert = (X509Certificate)admin.getAdminInformation().getX509Certificate();
            AuthenticationToken token = null;
            if (x509cert == null) {
            	if (admin.getAdminInformation().isSpecialUser() && (admin.getUsername() != null)) {
            		token = new AlwaysAllowLocalAuthenticationToken(new UsernamePrincipal(admin.getUsername()));
            	}
            } else {
            	final Set<X509Certificate> credentials = new HashSet<X509Certificate>();
                credentials.add(x509cert);
                final Set<X500Principal> principals = new HashSet<X500Principal>();
                principals.add(x509cert.getSubjectX500Principal());
                token = new X509CertificateAuthenticationToken(principals, credentials);
            }
            this.requestAdmin = token;
            this.requestSignature = (String) in.readObject();
            this.approvalRequestType = in.readInt();
            this.numOfRequiredApprovals = in.readInt();
            this.cAId = in.readInt();
            this.endEntityProfileId = in.readInt();
            final int stepSize = in.readInt();
            this.approvalStepsNrOfApprovals = new boolean[stepSize];
            for (int i = 0; i < approvalStepsNrOfApprovals.length; i++) {
                approvalStepsNrOfApprovals[i] = in.readBoolean();
            }
        }
        if (version == 4) {
        	// Version 4 after conversion to CESeCore where Admin was deprecated.
            this.requestAdmin = (AuthenticationToken) in.readObject();
            if (log.isTraceEnabled()) {
                log.trace("ApprovalRequest has a requestAdmin token of type: "+this.requestAdmin.getClass().getName());
            }
            if (this.requestAdmin instanceof LocalJvmOnlyAuthenticationToken) {
                if (log.isTraceEnabled()) {
                	log.trace("It was a LocalJvmOnlyAuthenticationToken so we will re-init it with local random token.");
                }
				LocalJvmOnlyAuthenticationToken localtoken = (LocalJvmOnlyAuthenticationToken) this.requestAdmin;
				localtoken.initRandomToken();
            } else if (this.requestAdmin instanceof CliAuthenticationToken) {
                // A Cli authentication token was probably used already and must thus be "re-registered"
                CliAuthenticationToken ctok = (CliAuthenticationToken)this.requestAdmin;
                CliAuthenticationTokenReferenceRegistry.INSTANCE.registerToken(ctok);
            }
            this.requestSignature = (String) in.readObject();
            this.approvalRequestType = in.readInt();
            this.numOfRequiredApprovals = in.readInt();
            this.cAId = in.readInt();
            this.endEntityProfileId = in.readInt();
            final int stepSize = in.readInt();
            this.approvalStepsNrOfApprovals = new boolean[stepSize];
            for (int i = 0; i < approvalStepsNrOfApprovals.length; i++) {
                approvalStepsNrOfApprovals[i] = in.readBoolean();
            }
        }
        if (version == 5) {
            // Version 5 after introducing approval profiles
            this.requestAdmin = (AuthenticationToken) in.readObject();
            if (log.isTraceEnabled()) {
                log.trace("ApprovalRequest has a requestAdmin token of type: "+this.requestAdmin.getClass().getName());
            }
            if (this.requestAdmin instanceof LocalJvmOnlyAuthenticationToken) {
                if (log.isTraceEnabled()) {
                    log.trace("It was a LocalJvmOnlyAuthenticationToken so we will re-init it with local random token.");
                }
                LocalJvmOnlyAuthenticationToken localtoken = (LocalJvmOnlyAuthenticationToken) this.requestAdmin;
                localtoken.initRandomToken();
            } else if (this.requestAdmin instanceof CliAuthenticationToken) {
                // A Cli authentication token was probably used already and must thus be "re-registered"
                CliAuthenticationToken ctok = (CliAuthenticationToken)this.requestAdmin;
                CliAuthenticationTokenReferenceRegistry.INSTANCE.registerToken(ctok);
            }
            this.requestSignature = (String) in.readObject();
            this.approvalRequestType = in.readInt();
            this.numOfRequiredApprovals = in.readInt();
            this.cAId = in.readInt();
            this.endEntityProfileId = in.readInt();
            final int stepSize = in.readInt();
            this.approvalStepsNrOfApprovals = new boolean[stepSize];
            for (int i = 0; i < approvalStepsNrOfApprovals.length; i++) {
                approvalStepsNrOfApprovals[i] = in.readBoolean();
            }
            
            this.approvalProfile = (ApprovalProfile) in.readObject();
            final boolean existSecondApprovalProfile = in.readBoolean();
            if(existSecondApprovalProfile) {
                this.secondApprovalProfile = (ApprovalProfile) in.readObject();
            } else {
                this.secondApprovalProfile = null;
            }
            
            this.approvalSteps = new HashMap<Integer, ApprovalStep>();
            int length = in.readInt(); 
            for (int i = 0; i < length; i++) {
                Integer stepId = (Integer)in.readObject();
                ApprovalStep step = (ApprovalStep)in.readObject();
                approvalSteps.put(stepId, step);
            }
            
            this.approvalStepsHandledMap = new HashMap<Integer, Boolean>();
            length = in.readInt(); 
            for (int i = 0; i < length; i++) {
                Integer stepId = (Integer)in.readObject();
                Boolean handled = in.readBoolean();
                approvalStepsHandledMap.put(stepId, handled);
            }
            
            this.oldApprovals = new ArrayList<Approval>();
            length = in.readInt(); 
            for (int i = 0; i < length; i++) {
                Approval approval = (Approval)in.readObject();
                oldApprovals.add(approval);
            }

        }
    }

}
