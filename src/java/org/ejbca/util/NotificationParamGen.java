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

import java.security.cert.Certificate;
import java.text.DateFormat;
import java.util.Date;
import java.util.HashMap;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import org.ejbca.core.model.ra.UserDataVO;
import org.ejbca.util.dn.DNFieldExtractor;

/**
 * Class generating parameter data for email notifications. Both
 * regular userdata and approval notifications.
 * 
 * All parameters isn't always set, it depends on the input data.
 * 
 * The following parameters can be set
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
 * ${user.TIMECREATED}             = The time the user was created
 * ${user.TIMEMODIFIED}            = The time the user was modified          
 *   
 * Variables used with approvals
 * 
 * ${approvalRequest.DATE}            = The time the approval request was created
 * ${approvalRequest.ID}              = The id of the approval request
 * ${approvalRequest.ABS.ID}          = The id of the approval request with out any '-' sign, used for presentation purposes.
 * ${approvalRequest.TYPE}            = The type of approval request
 * ${approvalRequest.APROVEURL}       = A URL to the review approval page with the current request.
 * ${approvalRequest.APPROVALSLEFT}   = The number of approvals remaining.
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
 * Variables used with  expiring certificates. 
 * ${expiringCert.CERTSERIAL}      = The serial number of the certificate about to expire 
 * ${expiringCert.EXPIREDATE}      = The date the certificate will expire
 * ${expiringCert.CERTSUBJECTDN}   = The certificate subject dn
 * ${expiringCert.CERTISSUERDN}    = The certificate issuer dn
 * The variables ${CN}, ${SN}, ${O}, ${OU}, ${C} are also available.
 * 
 * 
 * @author Philip Vendil 2006 sep 26
 *
 * @version $Id$
 */

public class NotificationParamGen {

  private HashMap params = new HashMap();	
  
  /** regexp pattern to match ${identifier} patterns */
  private final static Pattern PATTERN = Pattern.compile("\\$\\{(.+?)\\}");
  
  /**
   * Constructor that mainly should be used when notifying about expiring certificates.
   */
  public NotificationParamGen(UserDataVO user, Certificate expiringCert){
	  populate(user,null,null,null,null,null,null, null,null,null,null,expiringCert);
  }
	
  /**
   * Constructor that mainly should be used when generating user data notifications 
   */
  public NotificationParamGen(UserDataVO user, String approvalAdminDN){
	  populate(user,null,null,null,null,null,null, null,null,null,approvalAdminDN,null);
  }

  /**
   * Constructor that mainly should be used when generating approval notifications 
   */
  public NotificationParamGen(Date approvalRequestDate, Integer approvalRequestID, String approvalRequestType,
		  Integer numberOfApprovalLeft, String approvalRequestURL, String approveComment, String requestAdminUsername, String requestAdminDN,
          String approvalAdminUsername, String approvalAdminDN){
	  populate(null, approvalRequestDate, approvalRequestID, approvalRequestType,
			  numberOfApprovalLeft, approvalRequestURL, approveComment, requestAdminUsername, requestAdminDN,
               approvalAdminUsername, approvalAdminDN,null);
  }
  
  /**
   * Method used to retrieve the populated parameter hashmap with the notification text.
   * @return
   */
  public HashMap getParams(){
	  return params;
  }
  
  private void populate(UserDataVO user, 
		                Date approvalRequestDate, Integer approvalRequestID, String approvalRequestType,
		                Integer numberOfApprovalLeft, String approvalRequestURL, String approveComment,
		                String requestAdminUsername, String requestAdminDN,
		                String approvalAdminUsername, String approvalAdminDN,
		                Certificate expiringCert){
	  paramPut("NL", System.getProperty("line.separator"));
      String date = DateFormat.getDateTimeInstance(DateFormat.SHORT, DateFormat.SHORT).format(new Date());
      paramPut("DATE", date);

      paramPut("USERNAME", user.getUsername());
      paramPut("user.USERNAME", user.getUsername());

      paramPut("PASSWORD", user.getPassword());
      paramPut("user.PASSWORD", user.getPassword());

	  DNFieldExtractor dnfields = new DNFieldExtractor(user.getDN(), DNFieldExtractor.TYPE_SUBJECTDN);
	  paramPut("CN", dnfields.getField(DNFieldExtractor.CN, 0));
	  paramPut("user.CN", dnfields.getField(DNFieldExtractor.CN, 0));
	  paramPut("SN", dnfields.getField(DNFieldExtractor.SN, 0));
	  paramPut("user.SN", dnfields.getField(DNFieldExtractor.SN, 0));
	  paramPut("O", dnfields.getField(DNFieldExtractor.O, 0));
	  paramPut("user.O", dnfields.getField(DNFieldExtractor.O, 0));
	  paramPut("OU", dnfields.getField(DNFieldExtractor.OU, 0));
	  paramPut("user.OU", dnfields.getField(DNFieldExtractor.OU, 0));
	  paramPut("C", dnfields.getField(DNFieldExtractor.C, 0));
	  paramPut("user.E", dnfields.getField(DNFieldExtractor.E, 0));
	  String time = "(time not available)";
	  if (user.getTimeCreated() != null) {
		  time = DateFormat.getDateTimeInstance(DateFormat.SHORT, DateFormat.SHORT).format(user.getTimeCreated());
	  }
	  paramPut("user.TIMECREATED", time);		  
	  time = "(time not available)";
	  if (user.getTimeModified() != null) {
		  time = DateFormat.getDateTimeInstance(DateFormat.SHORT, DateFormat.SHORT).format(user.getTimeModified());
	  }
	  paramPut("user.TIMEMODIFIED", time);	  
	  
	  if(approvalRequestDate != null){
		  String requestDate = DateFormat.getDateTimeInstance(DateFormat.SHORT, DateFormat.SHORT).format(approvalRequestDate);
		  paramPut("approvalRequest.DATE", requestDate);	      
	  }else{
		  paramPut("approvalRequest.DATE", "");	
	  }
	  		  
	  paramPut("approvalRequest.ID", approvalRequestID);
	  if(approvalRequestID != null){
	    paramPut("approvalRequest.ABS.ID", new Integer(Math.abs(approvalRequestID.intValue())));
	  }
	  paramPut("approvalRequest.TYPE", approvalRequestType);
	  // Wrong spelled parameter kept for backwards compatibility
	  paramPut("approvalReqiest.APPROVALSLEFT", numberOfApprovalLeft);	      	  	  	  		  
	  paramPut("approvalRequest.APPROVALSLEFT", numberOfApprovalLeft);	      	  	  	  		  
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
	  paramPut("requestAdmin.E", dnfields.getField(DNFieldExtractor.E, 0));

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
	  paramPut("approvalAdmin.E", dnfields.getField(DNFieldExtractor.E, 0));
	  
	  if(expiringCert != null){
		  paramPut("expiringCert.CERTSERIAL",CertTools.getSerialNumberAsString(expiringCert));
		  String dateString = DateFormat.getDateTimeInstance(DateFormat.SHORT, DateFormat.SHORT).format(CertTools.getNotAfter(expiringCert));
		  paramPut("expiringCert.EXPIREDATE",dateString);
          paramPut("expiringCert.CERTSUBJECTDN",CertTools.getSubjectDN(expiringCert));
          paramPut("expiringCert.CERTISSUERDN",CertTools.getIssuerDN(expiringCert));          
	  }

	  
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
  
  /**
   * method that makes sure that a "" is inserted instead of null
   * @param key
   * @param value
   */
  private void paramPut(String key, Integer value){
	  if(value == null){
		  params.put(key, "");
	  }else{
		  params.put(key, value.toString());
	  }
  }
	
  // Help method used to populate a message 
  /**
   * Interpolate the patterns that exists on the input on the form '${pattern}'.
   * @param input the input content to be interpolated
   * @return the interpolated content
   */
  public static String interpolate(HashMap patterns, String input) {
      final Matcher m = PATTERN.matcher(input);
      final StringBuffer sb = new StringBuffer(input.length());
      while (m.find()) {
          // when the pattern is ${identifier}, group 0 is 'identifier'
          String key = m.group(1);
          String value = (String)patterns.get(key);
          // if the pattern does exists, replace it by its value
          // otherwise keep the pattern ( it is group(0) )
          if (value != null) {
              m.appendReplacement(sb, value);
          } else {
              // I'm doing this to avoid the backreference problem as there will be a $
              // if I replace directly with the group 0 (which is also a pattern)
              m.appendReplacement(sb, "");
              String unknown = m.group(0);
              sb.append(unknown);
          }
      }
      m.appendTail(sb);
      return sb.toString();
  }
  
}
