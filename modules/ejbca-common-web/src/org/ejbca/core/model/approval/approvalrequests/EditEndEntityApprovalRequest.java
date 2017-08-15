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
package org.ejbca.core.model.approval.approvalrequests;

import java.io.IOException;
import java.io.ObjectInput;
import java.io.ObjectOutput;
import java.util.ArrayList;
import java.util.List;

import javax.ejb.EJBException;

import org.apache.commons.lang.StringUtils;
import org.apache.log4j.Logger;
import org.cesecore.authentication.tokens.AuthenticationToken;
import org.cesecore.authorization.AuthorizationDeniedException;
import org.cesecore.certificates.ca.CADoesntExistsException;
import org.cesecore.certificates.ca.CaSession;
import org.cesecore.certificates.ca.CaSessionLocal;
import org.cesecore.certificates.ca.IllegalNameException;
import org.cesecore.certificates.certificate.exception.CertificateSerialNumberException;
import org.cesecore.certificates.certificateprofile.CertificateProfileSession;
import org.cesecore.certificates.endentity.EndEntityConstants;
import org.cesecore.certificates.endentity.EndEntityInformation;
import org.cesecore.certificates.endentity.ExtendedInformation;
import org.cesecore.util.CertTools;
import org.ejbca.core.ejb.hardtoken.HardTokenSession;
import org.ejbca.core.ejb.ra.EndEntityManagementSession;
import org.ejbca.core.ejb.ra.NoSuchEndEntityException;
import org.ejbca.core.ejb.ra.raadmin.EndEntityProfileSession;
import org.ejbca.core.model.approval.ApprovalDataText;
import org.ejbca.core.model.approval.ApprovalDataVO;
import org.ejbca.core.model.approval.ApprovalException;
import org.ejbca.core.model.approval.ApprovalRequest;
import org.ejbca.core.model.approval.ApprovalRequestExecutionException;
import org.ejbca.core.model.approval.ApprovalRequestHelper;
import org.ejbca.core.model.approval.WaitingForApprovalException;
import org.ejbca.core.model.approval.profile.ApprovalProfile;
import org.ejbca.core.model.ra.CustomFieldException;
import org.ejbca.core.model.ra.raadmin.EndEntityProfileValidationException;

/**
 * Approval Request created when trying to edit an end entity.
 * 
 * @version $Id$
 */
public class EditEndEntityApprovalRequest extends ApprovalRequest {

	private static final long serialVersionUID = -1L;

	private static final Logger log = Logger.getLogger(EditEndEntityApprovalRequest.class);
	
	private static final int LATEST_VERSION = 1;
		
	private EndEntityInformation newuserdata;
	private boolean clearpwd;
	private EndEntityInformation orguserdata;
	private boolean useOrgUsername;
	
	/** Constructor used in externalization only */
	public EditEndEntityApprovalRequest() {}

    public EditEndEntityApprovalRequest(EndEntityInformation newuserdata, boolean clearpwd, EndEntityInformation orguserdata,
            AuthenticationToken requestAdmin, String requestSignature, int cAId, int endEntityProfileId, ApprovalProfile approvalProfile) {
        super(requestAdmin, requestSignature, REQUESTTYPE_COMPARING, cAId, endEntityProfileId, approvalProfile);
        this.newuserdata = newuserdata;
        this.clearpwd = clearpwd;
        this.orguserdata = orguserdata;
    }
    
    public EditEndEntityApprovalRequest(EndEntityInformation newuserdata, boolean clearpwd, EndEntityInformation orguserdata,
            AuthenticationToken requestAdmin, String requestSignature, int cAId, int endEntityProfileId, ApprovalProfile approvalProfile, boolean useOrgUsername) {
        super(requestAdmin, requestSignature, REQUESTTYPE_COMPARING, cAId, endEntityProfileId, approvalProfile);
        this.newuserdata = newuserdata;
        this.clearpwd = clearpwd;
        this.orguserdata = orguserdata;
        this.useOrgUsername = useOrgUsername;
    }

	@Override
	public void execute() throws ApprovalRequestExecutionException {
		throw new IllegalStateException("This execution requires additional bean references.");
	}
	
    public void execute(EndEntityManagementSession endEntityManagementSession, final int approvalRequestID, 
            final AuthenticationToken lastApprovingAdmin) throws ApprovalRequestExecutionException {
        log.debug("Executing ChangeEndEntity for user:" + newuserdata.getUsername());
        
        // Add the ID of the approval request to the end entity as extended information.
        ExtendedInformation ext = newuserdata.getExtendedinformation();
        if(ext == null) {
            ext = orguserdata.getExtendedinformation();
        }
        if(ext == null) {
            ext = new ExtendedInformation();
        }
        ext.addEditEndEntityApprovalRequestId(approvalRequestID);
        newuserdata.setExtendedinformation(ext);
        
        try {
            if (newuserdata.getUsername().equals(orguserdata.getUsername())) {
        	    endEntityManagementSession.changeUserAfterApproval(getRequestAdmin(), newuserdata, clearpwd, approvalRequestID, lastApprovingAdmin);
            } else {
                endEntityManagementSession.changeUserAfterApproval(getRequestAdmin(), newuserdata, clearpwd, approvalRequestID, lastApprovingAdmin, orguserdata.getUsername());
            }
        } catch (AuthorizationDeniedException e) {
            throw new ApprovalRequestExecutionException("Authorization Denied :" + e.getMessage(), e);
        } catch (EndEntityProfileValidationException e) {
            throw new ApprovalRequestExecutionException("User Doesn't fullfil end entity profile :" + e.getMessage() + e.getMessage(), e);
        } catch (ApprovalException e) {
            throw new EJBException("This should never happen", e);
        } catch (WaitingForApprovalException e) {
            throw new EJBException("This should never happen", e);
        } catch (CADoesntExistsException e) {
            throw new ApprovalRequestExecutionException("CA does not exist:" + e.getMessage(), e);
		} catch (CertificateSerialNumberException e) {
		    throw new ApprovalRequestExecutionException("Error with the SubjectDN serialnumber :" + e.getErrorCode() + e.getMessage(), e);
        } catch (IllegalNameException e) {
            throw new ApprovalRequestExecutionException("The Subject DN failed constraints. " + e.getErrorCode() + e.getMessage(), e);
        } catch (NoSuchEndEntityException e) {
            throw new ApprovalRequestExecutionException("End entity not found.", e);
        } catch (CustomFieldException e) {
            throw new ApprovalRequestExecutionException("The end entity was not validated by a locally defined field validator", e);
        }
    }

    /**
     * Approval Id is genereated of This approval type (i.e AddEndEntityApprovalRequest) and UserName
     */
    @Override
    public int generateApprovalId() {	
        if (useOrgUsername) {
            return new String(getApprovalType() + ";" + orguserdata.getUsername() + ";" + getApprovalProfile().getProfileName()).hashCode();
        } else {
            return new String(getApprovalType() + ";" + newuserdata.getUsername() + ";" + getApprovalProfile().getProfileName()).hashCode();
        }
    }

    @Override
	public int getApprovalType() {		
		return ApprovalDataVO.APPROVALTYPE_EDITENDENTITY;
	}
    
    public EndEntityInformation getNewEndEntityInformation() {
        return newuserdata;
    }

	/** Returns a summary of the information in the request, without doing any database queries. See also the overloaded method */
	@Override
	public List<ApprovalDataText> getNewRequestDataAsText(AuthenticationToken admin) {
	    ArrayList<ApprovalDataText> retval = new ArrayList<>();
        retval.add(new ApprovalDataText("USERNAME",newuserdata.getUsername(),true,false));
        String passwordtext = "NOTSHOWN";
        if((newuserdata.getPassword() == null && !StringUtils.isEmpty(orguserdata.getPassword())) ||
           (!StringUtils.isEmpty(newuserdata.getPassword()) && orguserdata.getPassword() == null)) {            
            passwordtext = "NEWPASSWORD";           
        }       
        if(newuserdata.getPassword() != null && orguserdata.getPassword() != null){
            if(!newuserdata.getPassword().equals(orguserdata.getPassword())){
                passwordtext = "NEWPASSWORD";
            }
        }               
        retval.add(new ApprovalDataText("PASSWORD",passwordtext,true,true));
        retval.add(new ApprovalDataText("SUBJECTDN",CertTools.stringToBCDNString(newuserdata.getDN()),true,false));
        retval.add(getTextWithNoValueString("SUBJECTALTNAME",newuserdata.getSubjectAltName()));
        String dirattrs = newuserdata.getExtendedinformation() != null ? newuserdata.getExtendedinformation().getSubjectDirectoryAttributes() : null;
        retval.add(getTextWithNoValueString("SUBJECTDIRATTRIBUTES",dirattrs));
        retval.add(getTextWithNoValueString("EMAIL",newuserdata.getEmail()));
        retval.add(new ApprovalDataText("KEYRECOVERABLE",newuserdata.getKeyRecoverable() ? "YES" : "NO",true,true));
        retval.add(new ApprovalDataText("SENDNOTIFICATION",newuserdata.getSendNotification() ? "YES" : "NO",true,true));
        retval.add(new ApprovalDataText("STATUS",EndEntityConstants.getTranslatableStatusText(newuserdata.getStatus()),true,true));
        return retval;
	}

	public List<ApprovalDataText> getNewRequestDataAsText(CaSessionLocal caSession, EndEntityProfileSession endEntityProfileSession,
			CertificateProfileSession certificateProfileSession, HardTokenSession hardTokenSession) {
		ArrayList<ApprovalDataText> retval = new ArrayList<>();
		retval.add(new ApprovalDataText("USERNAME",newuserdata.getUsername(),true,false));
		String passwordtext = "NOTSHOWN";
		if((newuserdata.getPassword() == null && !StringUtils.isEmpty(orguserdata.getPassword())) ||
		   (!StringUtils.isEmpty(newuserdata.getPassword()) && orguserdata.getPassword() == null)) {			
			passwordtext = "NEWPASSWORD";			
		}		
		if(newuserdata.getPassword() != null && orguserdata.getPassword() != null){
			if(!newuserdata.getPassword().equals(orguserdata.getPassword())){
				passwordtext = "NEWPASSWORD";
			}
		}				
		retval.add(new ApprovalDataText("PASSWORD",passwordtext,true,true));
		retval.add(new ApprovalDataText("SUBJECTDN",CertTools.stringToBCDNString(newuserdata.getDN()),true,false));
		retval.add(getTextWithNoValueString("SUBJECTALTNAME",newuserdata.getSubjectAltName()));
		String dirattrs = newuserdata.getExtendedinformation() != null ? newuserdata.getExtendedinformation().getSubjectDirectoryAttributes() : null;
		retval.add(getTextWithNoValueString("SUBJECTDIRATTRIBUTES",dirattrs));
		retval.add(getTextWithNoValueString("EMAIL",newuserdata.getEmail()));
		String caname;
		try {
			caname = caSession.getCAInfoInternal(newuserdata.getCAId()).getName();
		} catch (CADoesntExistsException e) {
			caname = "NotExist";
		}
		retval.add(new ApprovalDataText("CA", caname, true, false));
		retval.add(new ApprovalDataText("ENDENTITYPROFILE", endEntityProfileSession.getEndEntityProfileName(newuserdata.getEndEntityProfileId()),true,false));		
		retval.add(new ApprovalDataText("CERTIFICATEPROFILE", certificateProfileSession.getCertificateProfileName(newuserdata.getCertificateProfileId()),true,false));
		final ExtendedInformation neweei = newuserdata.getExtendedinformation();
		if (neweei != null && neweei.getKeyStoreAlgorithmType() != null) {
		    String keyTypeString = neweei.getKeyStoreAlgorithmType();
		    if (neweei.getKeyStoreAlgorithmSubType() != null) {
		        keyTypeString += " " + neweei.getKeyStoreAlgorithmSubType();
		    }
		    retval.add(new ApprovalDataText("KEYALGORITHM", keyTypeString, true, false));
		}
		retval.add(ApprovalRequestHelper.getTokenName(hardTokenSession, newuserdata.getTokenType()));
		retval.add(getTextWithNoValueString("HARDTOKENISSUERALIAS", hardTokenSession.getHardTokenIssuerAlias(newuserdata.getHardTokenIssuerId())));
		retval.add(new ApprovalDataText("KEYRECOVERABLE",newuserdata.getKeyRecoverable() ? "YES" : "NO",true,true));
		retval.add(new ApprovalDataText("SENDNOTIFICATION",newuserdata.getSendNotification() ? "YES" : "NO",true,true));
		retval.add(new ApprovalDataText("STATUS",EndEntityConstants.getTranslatableStatusText(newuserdata.getStatus()),true,true));
		return retval;
	}
	
	private ApprovalDataText getTextWithNoValueString(String header, String data){
		if(data==null || data.equals("")){
			return new ApprovalDataText(header,"NOVALUE",true,true);
		}
		return new ApprovalDataText(header,data,true,false);
	}

	@Override
	public List<ApprovalDataText> getOldRequestDataAsText(AuthenticationToken admin) {
		throw new RuntimeException("This getOldRequestDataAsText requires additional bean references.");
	}

	public List<ApprovalDataText> getOldRequestDataAsText(AuthenticationToken admin, CaSession caSession, EndEntityProfileSession endEntityProfileSession,
			CertificateProfileSession certificateProfileSession, HardTokenSession hardTokenSession) {
		final List<ApprovalDataText> retval = new ArrayList<>();
		retval.add(new ApprovalDataText("USERNAME", orguserdata.getUsername(), true, false));
		retval.add(new ApprovalDataText("PASSWORD", "NOTSHOWN", true, true));
		retval.add(new ApprovalDataText("SUBJECTDN", CertTools.stringToBCDNString(orguserdata.getDN()), true, false));
		retval.add(getTextWithNoValueString("SUBJECTALTNAME", orguserdata.getSubjectAltName()));
		String dirattrs = orguserdata.getExtendedinformation() != null ? orguserdata.getExtendedinformation().getSubjectDirectoryAttributes() : null;
		retval.add(getTextWithNoValueString("SUBJECTDIRATTRIBUTES", dirattrs));
		retval.add(getTextWithNoValueString("EMAIL", orguserdata.getEmail()));
		String caname;
		try {
			caname = caSession.getCAInfo(admin,  orguserdata.getCAId()).getName();
		} catch (CADoesntExistsException e) {
			caname = "NotExist";
		} catch (AuthorizationDeniedException e) {
			caname = "AuthDenied";
		}
		retval.add(new ApprovalDataText("CA", caname, true, false));
		retval.add(new ApprovalDataText("ENDENTITYPROFILE", endEntityProfileSession.getEndEntityProfileName(orguserdata.getEndEntityProfileId()), true, false));		
		retval.add(new ApprovalDataText("CERTIFICATEPROFILE", certificateProfileSession.getCertificateProfileName(orguserdata.getCertificateProfileId()), true, false));
		retval.add(ApprovalRequestHelper.getTokenName(hardTokenSession, orguserdata.getTokenType()));
		retval.add(getTextWithNoValueString("HARDTOKENISSUERALIAS", hardTokenSession.getHardTokenIssuerAlias(orguserdata.getHardTokenIssuerId())));
		retval.add(new ApprovalDataText("KEYRECOVERABLE", orguserdata.getKeyRecoverable() ? "YES" : "NO", true, true));
		retval.add(new ApprovalDataText("SENDNOTIFICATION", orguserdata.getSendNotification() ? "YES" : "NO", true, true));
		retval.add(new ApprovalDataText("STATUS", EndEntityConstants.getTranslatableStatusText(orguserdata.getStatus()), true, true));
		return retval;
	}

	@Override
	public boolean isExecutable() {		
		return true;
	}
	
	@Override
	public void writeExternal(ObjectOutput out) throws IOException {
		super.writeExternal(out);
		out.writeInt(LATEST_VERSION);
		out.writeObject(newuserdata);
		out.writeBoolean(clearpwd);
		out.writeObject(orguserdata);
	}

	@Override
	public void readExternal(ObjectInput in) throws IOException, ClassNotFoundException {        
		super.readExternal(in);
        int version = in.readInt();
        if(version == 1){
    		newuserdata = (EndEntityInformation) in.readObject();
    		clearpwd = in.readBoolean();
    		orguserdata = (EndEntityInformation) in.readObject();
        }
	}
}
