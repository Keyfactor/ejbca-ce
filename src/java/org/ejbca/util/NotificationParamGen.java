/*************************************************************************
 *                                                                       *
 *  EJBCA: The OpenSource Certificate Authority                          *
 *                                                                       *
 *  This software is free software; you can redistribute it and/or       *
 *  modify it under the terms of the GNU Lesser General Public           *
 *  License as published by the Free Software Foundation; either         *
 *  version 2.1 of the License, or any later version.                    *
 *                                                                       *
 *  See terms of license at gnu.org.                                     *
 *                                                                       *
 *************************************************************************/
package org.ejbca.util;

import java.text.DateFormat;
import java.util.Date;
import java.util.HashMap;

import org.ejbca.core.model.ra.raadmin.DNFieldExtractor;

/**
 * Class generating parameter data for email notifications. Both
 * regular userdata and approval notifications.
 * 
 * All parameters isn't always set, it depends on the input data.
 * 
 * The follwing parameters can be set
 * ${NL}                           = New Line in message
 * ${DATE} or ${current.DATE}      = The current date
 * 
 * Variables used with userdata
 * ${USERNAME} or ${user.USERNAME} = The users username
 * ${PASSWORD} or ${user.PASSWORD} = The users password 
 * ${CN} or ${user.CN}             = The common name of the user.
 * ${SN} or ${user.SN}             = The serial number (in DN) of the user.
 * ${O} or ${user.O}               = The user's organization
 * ${OU} or ${user.OU}             = The user's organization unit
 * ${C} or ${user.C}               = The user's country            
 *   
 * Variables used with approvals
 * 
 * ${approvalRequest.DATE}            = The time the approval request was created
 * ${approvalRequest.ID}              = The id of the approval request
 * ${approvalRequest.TYPE}            = The type of approval request
 * ${approvalRequest.APROVEURL}       = A URL to the review approval page with the current request.
 * ${approvalReqiest.APPROVALSLEFT}   = The number of approvals remaining.
 * ${approvalRequest.APPROVALCOMMENT} = The comment made by the approving/rejecting administrator
 * 
 * ${requestAdmin.USERNAME}         = The requesting administrator's username
 * ${requestAdmin.CN}               = The common name of the requesting administrator.
 * ${requestAdmin.SN}               = The common name of the requesting administrator.
 * ${requestAdmin.O}                = The requesting administrator's organization
 * ${requestAdmin.OU}               = The requesting administrator's organization unit
 * ${requestAdmin.C}                = The requesting administrator's country 
 * 
 * ${approvalAdmin.USERNAME}        = The requesting administrator's username
 * ${approvalAdmin.CN}              = The common name of the requesting administrator.
 * ${approvalAdmin.SN}              = The common name of the requesting administrator.
 * ${approvalAdmin.O}               = The requesting administrator's organization
 * ${approvalAdmin.OU}              = The requesting administrator's organization unit
 * ${approvalAdmin.C}               = The requesting administrator's country  
 * 
 * @author Philip Vendil 2006 sep 26
 *
 * @version $Id: NotificationParamGen.java,v 1.1 2006-09-27 09:28:27 herrvendil Exp $
 */

public class NotificationParamGen {

  private HashMap params = new HashMap();	
	
  /**
   * Constuctor that mainly should be used when generating user data notifications 
   */
  public NotificationParamGen(String userUsername, String userPassword, String userDN){
	  populate(userUsername, userPassword, userDN,null,null,null,null,null,null, null,null,null,null);
  }

  /**
   * Constuctor that mainly should be used when generating approval notifications 
   */
  public NotificationParamGen(Date approvalRequestDate, Integer approvalRequestID, String approvalRequestType,
		  Integer numberOfApprovalLeft, String approvalRequestURL, String approveComment, String requestAdminUsername, String requestAdminDN,
          String approvalAdminUsername, String approvalAdminDN){
	  populate(null, null, null, approvalRequestDate, approvalRequestID, approvalRequestType,
			  numberOfApprovalLeft, approvalRequestURL, approveComment, requestAdminUsername, requestAdminDN,
               approvalAdminUsername, approvalAdminDN);
  }
  
  /**
   * Method used to retrieve the populated parameter hashmap with the notification text.
   * @return
   */
  public HashMap getParams(){
	  return params;
  }
  
  private void populate(String userUsername, String userPassword, String userDN, 
		                Date approvalRequestDate, Integer approvalRequestID, String approvalRequestType,
		                Integer numberOfApprovalLeft, String approvalRequestURL, String approveComment,
		                String requestAdminUsername, String requestAdminDN,
		                String approvalAdminUsername, String approvalAdminDN){
      params.put("NL", System.getProperty("line.separator"));
      String date = DateFormat.getDateTimeInstance(DateFormat.SHORT, DateFormat.SHORT).format(new Date());
      params.put("DATE", date);

      paramPut("USERNAME", userUsername);
      paramPut("user.USERNAME", userUsername);

      paramPut("PASSWORD", userPassword);
      paramPut("user.PASSWORD", userPassword);

      if(userDN != null){
    	  userDN = "";
      }
	  DNFieldExtractor dnfields = new DNFieldExtractor(userDN, DNFieldExtractor.TYPE_SUBJECTDN);
	  paramPut("CN", dnfields.getField(DNFieldExtractor.CN, 0));
	  paramPut("user.CN", dnfields.getField(DNFieldExtractor.CN, 0));
	  paramPut("SN", dnfields.getField(DNFieldExtractor.SN, 0));
	  paramPut("user.SN", dnfields.getField(DNFieldExtractor.SN, 0));
	  paramPut("O", dnfields.getField(DNFieldExtractor.O, 0));
	  paramPut("user.O", dnfields.getField(DNFieldExtractor.O, 0));
	  paramPut("OU", dnfields.getField(DNFieldExtractor.OU, 0));
	  paramPut("user.OU", dnfields.getField(DNFieldExtractor.OU, 0));
	  paramPut("C", dnfields.getField(DNFieldExtractor.C, 0));
	  paramPut("user.C", dnfields.getField(DNFieldExtractor.C, 0));
	  
	  
	  if(approvalRequestDate != null){
		  String requestDate = DateFormat.getDateTimeInstance(DateFormat.SHORT, DateFormat.SHORT).format(approvalRequestDate);
		  params.put("approvalRequest.DATE", requestDate);	      
	  }else{
		  params.put("approvalRequest.DATE", "");	
	  }
	  		  
	  paramPut("approvalRequest.ID", approvalRequestID.toString());	      	  
	  paramPut("approvalRequest.TYPE", approvalRequestType);	      	 	  		  
	  paramPut("approvalReqiest.APPROVALSLEFT", numberOfApprovalLeft.toString());	      	  	  	  		  
	  paramPut("approvalRequest.APROVEURL", approvalRequestURL);	      
	  paramPut("approvalRequest.APPROVALCOMMENT", approveComment);	      
	  paramPut("requestAdmin.USERNAME", requestAdminUsername);	  

	  if(requestAdminDN != null){
		  requestAdminDN = "";
	  }
	  dnfields = new DNFieldExtractor(requestAdminDN, DNFieldExtractor.TYPE_SUBJECTDN);	      
	  paramPut("requestAdmin.CN", dnfields.getField(DNFieldExtractor.CN, 0));	      
	  paramPut("requestAdmin.SN", dnfields.getField(DNFieldExtractor.SN, 0));
	  paramPut("requestAdmin.O", dnfields.getField(DNFieldExtractor.O, 0));
	  paramPut("requestAdmin.OU", dnfields.getField(DNFieldExtractor.OU, 0));
	  paramPut("requestAdmin.C", dnfields.getField(DNFieldExtractor.C, 0));

	  paramPut("requestAdmin.USERNAME", approvalAdminUsername);
	  
	  if(approvalAdminDN == null){
		  approvalAdminDN = "";
	  }
	  dnfields = new DNFieldExtractor(approvalAdminDN, DNFieldExtractor.TYPE_SUBJECTDN);	      
	  paramPut("approvalAdmin.CN", dnfields.getField(DNFieldExtractor.CN, 0));	      
	  paramPut("approvalAdmin.SN", dnfields.getField(DNFieldExtractor.SN, 0));
	  paramPut("approvalAdmin.O", dnfields.getField(DNFieldExtractor.O, 0));
	  paramPut("approvalAdmin.OU", dnfields.getField(DNFieldExtractor.OU, 0));
	  paramPut("approvalAdmin.C", dnfields.getField(DNFieldExtractor.C, 0));

	  
  }
  
  /**
   * method that makes sure that a "" is inserted instead of null
   * @param key
   * @param value
   */
  private void paramPut(String key, String value){
	  if(value == null){
		  params.put(key, "");
	  }else{
		  params.put(key, value);
	  }
  }
	
}
