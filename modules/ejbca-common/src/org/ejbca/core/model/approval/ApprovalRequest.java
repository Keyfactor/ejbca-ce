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
import java.util.Date;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

import javax.security.auth.x500.X500Principal;

import org.apache.log4j.Logger;
import org.cesecore.authentication.tokens.AlwaysAllowLocalAuthenticationToken;
import org.cesecore.authentication.tokens.AuthenticationToken;
import org.cesecore.authentication.tokens.LocalJvmOnlyAuthenticationToken;
import org.cesecore.authentication.tokens.UsernamePrincipal;
import org.cesecore.authentication.tokens.X509CertificateAuthenticationToken;
import org.cesecore.util.Base64;
import org.cesecore.util.CertTools;
import org.ejbca.core.ejb.authentication.cli.CliAuthenticationToken;
import org.ejbca.core.ejb.authentication.cli.CliAuthenticationTokenReferenceRegistry;
import org.ejbca.core.model.approval.profile.ApprovalProfile;
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

    private AuthenticationToken requestAdmin = null; 
    private String requestSignature = null;
    private int approvalRequestType = REQUESTTYPE_SIMPLE;
    /**
     * @deprecated since 6.6.0 kept only for 100% uptime reasons.
     */
    @Deprecated
    private int numOfRequiredApprovals = 0;
    private int cAId = 0;
    private int endEntityProfileId = 0;
    private boolean[] approvalSteps = { false };
    
    private ApprovalProfile approvalProfile;
    
    /** Admins who have edited the request, in order of time. The last admin will not be allowed to approve the request. */
    private List<TimeAndAdmin> editedByAdmins = new ArrayList<>();
    
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
    protected ApprovalRequest(AuthenticationToken requestAdmin, String requestSignature, int approvalRequestType, int cAId, int endEntityProfileId,
            ApprovalProfile approvalProfile) {
        super();
        setRequestAdmin(requestAdmin);
        this.requestSignature = requestSignature;
        this.approvalRequestType = approvalRequestType;
        this.cAId = cAId;
        this.endEntityProfileId = endEntityProfileId;
        this.approvalProfile = approvalProfile;
    }

    /**
     * Main constructor of an approval request.
     * 
     * @param requestAdminCert the certificate of the requesting admin
     * @param requestSignature signature of the requester (OPTIONAL, for future use)
     * @param approvalRequestType one of TYPE_ constants
     * @param cAId the related cAId of the request that the approver must be authorized to or ApprovalDataVO.ANY_CA in applicable to any ca
     * @param endEntityProfileId the related profile id that the approver must be authorized to or ApprovalDataVO.ANY_ENDENTITYPROFILE if applicable
     *            to any end entity profile
     * @param numberOfSteps that this type approval request supports.
     */
    protected ApprovalRequest(AuthenticationToken requestAdmin, String requestSignature, int approvalRequestType, int cAId, int endEntityProfileId,
            int numberOfSteps, ApprovalProfile approvalProfile) {
        super();
        setRequestAdmin(requestAdmin);
        this.requestSignature = requestSignature;
        this.approvalRequestType = approvalRequestType;
        this.cAId = cAId;
        this.endEntityProfileId = endEntityProfileId;
        
        this.approvalProfile = approvalProfile;
        this.approvalSteps = new boolean[numberOfSteps];
    }

    /** Constructor used in externalization only */
    public ApprovalRequest() {
    }
    
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
     * Generate an approval hash (called ID which is confusing since there is a unique requestID as well) for this type of approval, the same request 
     * i.e the same admin want's to do the same thing twice should result in the same approval hash. This is the value that will be stored in the 
     * ApprovalData.approvalId column.
     * This hash is not used to identify a specific request, but is used to be able to compare to requests if they are for the same thing. As an 
     * example trying to add the exact same user twice will result in the same approval hash so it is possible to find an already existing request 
     * for adding this user. 
     * 
     * @return a hash code for the action the request is for, should be the same code every time the same action is performed.
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
        return getApprovalProfile().getRequestExpirationPeriod();
    }

    /**
     * Should return the time in millisecond that the approval should be valid or Long.MAX_VALUE if it should never expire
     * 
     * Default if will return the value defined in the ejbca.properties
     */
    public long getApprovalValidity() {
        return getApprovalProfile().getApprovalExpirationPeriod();
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
    
    public void setApprovalProfile(final ApprovalProfile approvalProfile) {
        this.approvalProfile = approvalProfile;
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
     * 
     * @param admin the admin we want to check if has edited the request _last_
     * @return true if admin was the last of admins who edited this approval request, false otherwise
     */
    public boolean isEditedByMe(final AuthenticationToken admin) {
        // admin who edited last can't approve
        if (editedByAdmins.isEmpty()) {
            return false;
        } else {
            final AuthenticationToken lastEditedBy = editedByAdmins.get(editedByAdmins.size()-1).getAdmin();
            return lastEditedBy.equals(admin);
        }
    }
    
    /** When an approval request is edited, we keep a list of which admin edited a request
     * 
     * @param admin an admin that edited a request
     */
    public void addEditedByAdmin(final AuthenticationToken admin) {
        editedByAdmins.add(new TimeAndAdmin(new Date(), admin));
    }
    
    /** When an approval request is edited, we keep a list of which admin edited a request
     * 
     * @return a list of admins that has edited a request
     */
    public List<TimeAndAdmin> getEditedByAdmins() {
        return editedByAdmins;
    }

    /**
     * Returns true if this step have been executed before.
     * 
     * @param step to query
     * 
     * @deprecated this method denotes a outdated feature pertaining to hard tokens, and should not be used. 
     */
    @Deprecated
    public boolean isStepDone(int step) {
        return approvalSteps[step];
    }

    /**
     * Marks the given step as done.
     * 
     * @param step to query
     */
    public void markStepAsDone(int step) {
        approvalSteps[step] = true;
    }

    /**
     * Returns the number of steps that this approval request supports.
     * 
     * @deprecated this method denotes a outdated feature pertaining to hard tokens, and should not be used. 
     */
    @Deprecated
    public int getNumberOfApprovalSteps() {
        return approvalSteps.length;
    }

    @Override
    public void writeExternal(ObjectOutput out) throws IOException {
        out.writeInt(LATEST_BASE_VERSION);
        out.writeObject(this.requestAdmin);
        out.writeObject(this.requestSignature);
        out.writeInt(this.approvalRequestType);
        out.writeInt(this.numOfRequiredApprovals);
        out.writeInt(this.cAId);
        out.writeInt(this.endEntityProfileId);
        out.writeInt(this.approvalSteps.length);
        for (int i = 0; i < approvalSteps.length; i++) {
            out.writeBoolean(approvalSteps[i]);
        }
        
        out.writeObject(approvalProfile);
        out.writeObject(editedByAdmins);
    }

    @SuppressWarnings("unchecked")
    @Override
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
            this.approvalSteps = new boolean[1];
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
            this.approvalSteps = new boolean[1];
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
            	final Set<X509Certificate> credentials = new HashSet<>();
                credentials.add(x509cert);
                final Set<X500Principal> principals = new HashSet<>();
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
            this.approvalSteps = new boolean[stepSize];
            for (int i = 0; i < approvalSteps.length; i++) {
                approvalSteps[i] = in.readBoolean();
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
            if (log.isTraceEnabled()) {
                log.trace("ApprovalRequest have "+stepSize+" approval steps.");                
            }
            this.approvalSteps = new boolean[stepSize];
            for (int i = 0; i < approvalSteps.length; i++) {
                approvalSteps[i] = in.readBoolean();
            }
            if (log.isDebugEnabled()) {
                log.debug("ApprovalRequest (version 4) of type "+getApprovalType()+" read.");
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
            if (log.isTraceEnabled()) {
                log.trace("ApprovalRequest have "+stepSize+" approval steps.");                
            }
            this.approvalSteps = new boolean[stepSize];
            for (int i = 0; i < approvalSteps.length; i++) {
                approvalSteps[i] = in.readBoolean();
            }
            this.approvalProfile = (ApprovalProfile) in.readObject();
            this.editedByAdmins = (List<TimeAndAdmin>) in.readObject();
            if (log.isDebugEnabled()) {
                log.debug("ApprovalRequest (version 5) of type "+getApprovalType()+" read.");
            }
        }
    }

}
