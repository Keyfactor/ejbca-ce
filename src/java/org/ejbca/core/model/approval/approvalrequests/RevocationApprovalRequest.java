package org.ejbca.core.model.approval.approvalrequests;

import java.io.IOException;
import java.io.ObjectInput;
import java.io.ObjectOutput;
import java.math.BigInteger;
import java.rmi.RemoteException;
import java.util.ArrayList;
import java.util.List;

import javax.ejb.CreateException;
import javax.ejb.EJBException;
import javax.ejb.FinderException;
import javax.ejb.RemoveException;
import javax.naming.Context;
import javax.naming.NamingException;

import org.apache.log4j.Logger;
import org.ejbca.core.ejb.ra.IUserAdminSessionHome;
import org.ejbca.core.ejb.ra.IUserAdminSessionRemote;
import org.ejbca.core.model.approval.ApprovalDataText;
import org.ejbca.core.model.approval.ApprovalDataVO;
import org.ejbca.core.model.approval.ApprovalException;
import org.ejbca.core.model.approval.ApprovalRequest;
import org.ejbca.core.model.approval.ApprovalRequestExecutionException;
import org.ejbca.core.model.approval.WaitingForApprovalException;
import org.ejbca.core.model.authorization.AuthorizationDeniedException;
import org.ejbca.core.model.ca.crl.RevokedCertInfo;
import org.ejbca.core.model.log.Admin;
import org.ejbca.core.model.ra.AlreadyRevokedException;
import org.ejbca.core.model.ra.NotFoundException;
import org.ejbca.ui.web.admin.rainterface.RevokedInfoView;

public class RevocationApprovalRequest extends ApprovalRequest {

	private static final long serialVersionUID = -1L;

	private static final Logger log = Logger.getLogger(RevocationApprovalRequest.class);
	
	private static final int LATEST_VERSION = 1;	

	private int approvalType = -1;
	private String username = null;
	private BigInteger certificateSerialNumber = null;
	private String issuerDN = null;
	private int reason = -2;
	
	/**
	 * Constuctor used in externaliziation only
	 */
	public RevocationApprovalRequest() {}

	/**
	 * Construct an approvalrequest for the revocation of a certificate.
	 * @param certificateSerialNumber
	 * @param issuerDN
	 * @param username
	 * @param reason
	 * @param requestAdmin
	 * @param numOfReqApprovals
	 * @param cAId
	 * @param endEntityProfileId
	 */
	public RevocationApprovalRequest(BigInteger certificateSerialNumber, String issuerDN, String username,
			int reason, Admin requestAdmin, int numOfReqApprovals, int cAId, int endEntityProfileId) {
		super(requestAdmin, null, REQUESTTYPE_SIMPLE, numOfReqApprovals, cAId, endEntityProfileId);
		this.approvalType = ApprovalDataVO.APPROVALTYPE_REVOKECERTIFICATE;
		this.username = username;
		this.reason = reason;
		this.certificateSerialNumber = certificateSerialNumber;
		this.issuerDN = issuerDN; 
	} // RevocationApprovalRequest

	/**
	 * Constructs an approvalrequest for the revocation and optional removal of an end entity.
	 * @param deleteAfterRevoke
	 * @param username
	 * @param reason
	 * @param requestAdmin
	 * @param numOfReqApprovals
	 * @param cAId
	 * @param endEntityProfileId
	 */
	public RevocationApprovalRequest(boolean deleteAfterRevoke, String username,
			int reason, Admin requestAdmin, int numOfReqApprovals, int cAId, int endEntityProfileId) {
		super(requestAdmin, null, REQUESTTYPE_SIMPLE, numOfReqApprovals, cAId, endEntityProfileId);
		if (deleteAfterRevoke) {
			this.approvalType = ApprovalDataVO.APPROVALTYPE_REVOKEANDDELETEENDENTITY;
		} else {
			this.approvalType = ApprovalDataVO.APPROVALTYPE_REVOKEENDENTITY;
		}
		this.username = username;
		this.reason = reason;
		this.certificateSerialNumber = null;
		this.issuerDN = null;
	} // RevocationApprovalRequest

	/**
	 * A main function of the ApprovalRequest, the execute() method
	 * is run when all required approvals have been made.
	 * 
	 * execute should perform the action or nothing if the requesting admin
	 * is supposed to try this action again.
	 */
	public void execute() throws ApprovalRequestExecutionException {
		log.debug("Executing " + ApprovalDataVO.APPROVALTYPENAMES[approvalType] + " (" + approvalType + ").");

		try {
		    Context ctx = new javax.naming.InitialContext();
		    IUserAdminSessionHome useradminsessionhome = (IUserAdminSessionHome) javax.rmi.PortableRemoteObject.narrow(ctx.lookup("UserAdminSession"),
		    		IUserAdminSessionHome.class);
			IUserAdminSessionRemote useradminsession = useradminsessionhome.create();
			switch (approvalType) {
				case ApprovalDataVO.APPROVALTYPE_REVOKEENDENTITY:
					useradminsession.revokeUser(getRequestAdmin(), username, reason);
					break;
				case ApprovalDataVO.APPROVALTYPE_REVOKEANDDELETEENDENTITY:
					useradminsession.revokeAndDeleteUser(getRequestAdmin(), username, reason);
					break;
				case ApprovalDataVO.APPROVALTYPE_REVOKECERTIFICATE:
					useradminsession.revokeCert(getRequestAdmin(), certificateSerialNumber, issuerDN, username, reason);
					break;
				default:
					log.error("Unknown approval type " + approvalType);
					break;
			}
		} catch (CreateException e) {
			throw new ApprovalRequestExecutionException("Error creating userdata session", e);
		} catch (AuthorizationDeniedException e) {
			throw new ApprovalRequestExecutionException("Authorization Denied :" + e.getMessage(), e);
		} catch (ApprovalException e) {
			throw new EJBException("This should never happen",e);
		} catch (WaitingForApprovalException e) {
			throw new EJBException("This should never happen",e);
		} catch (AlreadyRevokedException e) {
			throw new ApprovalRequestExecutionException("End entity " + username + " was already revoked at execution time.");
		} catch (FinderException e) {
			throw new ApprovalRequestExecutionException("Could not find object.",e);
		} catch (NotFoundException e) {
			throw new ApprovalRequestExecutionException("Could not find object.",e);
		} catch (RemoveException e) {
			throw new ApprovalRequestExecutionException("Could not remove object.",e);
		} catch (NamingException e) {
			throw new EJBException(e);
		} catch (RemoteException e) {
			throw new EJBException(e);
		}
	} // execute

	/**
	 * Method that should generate an approval id for this type of
	 * approval, the same request i.e the same admin want's to do the
	 * same thing twice should result in the same approvalId.
	 */
	public int generateApprovalId() {
		return generateApprovalId(getApprovalType(), username, reason, certificateSerialNumber, issuerDN);
	} // generateApprovalId

	static public int generateApprovalId(int approvalType, String username, int reason, BigInteger certificateSerialNumber, String issuerDN) {
		String idString = approvalType + ";" + username + ";" + reason +";";
		if ( certificateSerialNumber != null && issuerDN != null ) {
			idString += certificateSerialNumber + ";" + issuerDN + ";";
		}
		return idString.hashCode();
	} // generateApprovalId

	public int getApprovalType() {		
		return approvalType;
	} // getApprovalType

	/**
	 * This method should return the request data in text representation.
	 * This text is presented for the approving administrator in order
	 * for him to make a decision about the request.
	 * 
	 * Should return a List of ApprovalDataText, one for each row
	 */
	public List getNewRequestDataAsText(Admin admin) {
		ArrayList retval = new ArrayList();
		if ( username != null ) {
			retval.add(new ApprovalDataText("USERNAME",username,true,false));
		}
		if ( reason == RevokedCertInfo.NOT_REVOKED) {
			retval.add(new ApprovalDataText("REASON","UNREVOKE",true,true));
		} else {
			retval.add(new ApprovalDataText("REASON",RevokedInfoView.reasontexts[reason],true,true));
		}
		if ( certificateSerialNumber != null && issuerDN != null ) {
			retval.add(new ApprovalDataText("CERTSERIALNUMBER",certificateSerialNumber.toString(16),true,false));
			retval.add(new ApprovalDataText("ISSUERDN",issuerDN,true,false));
		}
		return retval;
	}
	
	/**
	 * This method should return the original request data in text representation.
	 * Should only be implemented by TYPE_COMPARING ApprovalRequests.
	 * TYPE_SIMPLE requests should return null;
	 * 
	 * This text is presented for the approving administrator for him to
	 * compare of what will be done.
	 * 
	 * Should return a Collection of ApprovalDataText, one for each row
	 */
	public List getOldRequestDataAsText(Admin admin) {
		return null;
	}

	/**
	 * Should return true if the request if of the type that should be executed
	 * by the last approver.
	 * 
	 * False if the request admin should do a polling action to try again.
	 */
	public boolean isExecutable() {		
		return true;
	}
	
	public void writeExternal(ObjectOutput out) throws IOException {
		super.writeExternal(out);
		out.writeInt(LATEST_VERSION);
		out.writeObject(username);
		out.writeInt(reason);
		out.writeInt(approvalType);
		out.writeObject(certificateSerialNumber);
		out.writeObject(issuerDN);
	}

	public void readExternal(ObjectInput in) throws IOException, ClassNotFoundException {        
		super.readExternal(in);
        int version = in.readInt();
        if(version == 1){
    		username = (String) in.readObject();
    		reason = in.readInt();
    		approvalType = in.readInt();
    		certificateSerialNumber = (BigInteger) in.readObject();
    		issuerDN = (String) in.readObject();
        }

	}
}
