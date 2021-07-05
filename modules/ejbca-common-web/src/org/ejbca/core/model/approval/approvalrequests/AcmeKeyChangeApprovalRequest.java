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

import org.cesecore.authentication.tokens.AuthenticationToken;
import org.ejbca.core.model.approval.ApprovalDataText;
import org.ejbca.core.model.approval.ApprovalDataVO;
import org.ejbca.core.model.approval.ApprovalRequest;
import org.ejbca.core.model.approval.ApprovalRequestExecutionException;
import org.ejbca.core.model.approval.profile.ApprovalProfile;

/**
 * Approval Request created when calling for the ACME keyChange resource.
 */
public class AcmeKeyChangeApprovalRequest extends ApprovalRequest {
   
	private static final int LATEST_VERSION = 1;

	private String acmeAccountId;
	private int caId;
	private int endEntityProfileId;
	
	/** Default constructor. */
	public AcmeKeyChangeApprovalRequest() {}

	/**
	 * Creates an approval request to register a new ACME account using the newAccount resource.
	 * 
	 * @param token the authorization token.
	 * @param approvalProfile the approval profile associated with the ACME alias account registration.
	 * @param caId the ID of the CA.
	 * @param endEntityProfileId the ID of the end entity profile.
	 * @param acmeAccountId the ACME account ID.
	 */
    public AcmeKeyChangeApprovalRequest(final AuthenticationToken token, final ApprovalProfile approvalProfile, final int caId, final int endEntityProfileId, final String acmeAccountId) {
        super(token, null, REQUESTTYPE_SIMPLE, caId, endEntityProfileId, approvalProfile, /* validation results */ null);
        this.acmeAccountId = acmeAccountId;
        this.caId = caId;
        this.endEntityProfileId = endEntityProfileId;
    }

	@Override
	public void execute() throws ApprovalRequestExecutionException {
		// noop
	}

	/**
	 * Method that should generate an approval id for this type of
	 * approval, the same request i.e the same admin want's to do the
	 * same thing twice should result in the same approvalId.
	 */
	@Override
    public int generateApprovalId() {
		return (getApprovalType() + ";" + getApprovalProfile().getProfileName() + ";" + acmeAccountId).hashCode();
	}

	@Override
    public int getApprovalType() {
		return ApprovalDataVO.APPROVALTYPE_ACME_ACCOUNT_KEYCHANGE;
	}

	/**
	 * This method should return the request data in text representation.
	 * This text is presented for the approving administrator in order
	 * for him to make a decision about the request.
	 *
	 * Should return a List of ApprovalDataText, one for each row
	 */
	@Override
	public List<ApprovalDataText> getNewRequestDataAsText(AuthenticationToken admin) {
		ArrayList<ApprovalDataText> retval = new ArrayList<ApprovalDataText>();
		if (acmeAccountId != null) {
			retval.add(new ApprovalDataText("ACMEACCOUNTID", acmeAccountId, true, false));
		}
		retval.add(new ApprovalDataText("CAID", Integer.toString(caId), true, false));
		retval.add(new ApprovalDataText("EEPID", Integer.toString(endEntityProfileId), true, false));
		return retval;
	}

	@Override
	public List<ApprovalDataText> getOldRequestDataAsText(AuthenticationToken admin) {
		return null;
	}

	@Override
    public boolean isExecutable() {
		return false;
	}

	@Override
    public void writeExternal(ObjectOutput out) throws IOException {
		super.writeExternal(out);
		out.writeInt(LATEST_VERSION);
		out.writeObject(acmeAccountId);
		out.writeInt(caId);
		out.writeInt(endEntityProfileId);
	}

	@Override
    public void readExternal(ObjectInput in) throws IOException, ClassNotFoundException {
		super.readExternal(in);
        int version = in.readInt();
        if(version == 1) {
    		this.acmeAccountId = (String) in.readObject();
    		this.caId = in.readInt();
    		this.endEntityProfileId = in.readInt();
        }
	}
}
