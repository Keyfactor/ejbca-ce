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

import java.util.ArrayList;
import java.util.StringTokenizer;

import org.apache.log4j.Logger;
import org.ejbca.config.EjbcaConfiguration;

/**
 * Util class with methods to get information about calling classes
 * Used to avoid circular method invocations

Approval configuration
======================

There are three levels of configuration for approval.

1. Globally excluded classes. When these call functions that normally require approval, approval is not required. This is configured, as a comma separated list, in the ejbca.properties property approval.excludedClasses (for example approval.excludedClasses=org.ejbca.extra.caservice.ExtRACAProcess).
The check for these globally excluded classes are done in ApprovalExecutorUtil. The list of globally excluded classes are kept as a String in ApprovalExecutorUtil.

2. Fine grained excluded classes/methods. This is configured, hard coded, within a session bean that uses approval. These fine grained classes and methods uses an array of ApprovalOverridableClassName, which is passed to ApprovalExecutorUtil. The check itself is also done in ApprovalExecutorUtil. The array can be defined per approval function.
For example:
private static final ApprovalOveradableClassName[] NONAPPROVABLECLASSNAMES_SETUSERSTATUS = {
		new ApprovalOveradableClassName("org.ejbca.core.ejb.ra.EndEntityManagementSessionBean","revokeUser"),
		new ApprovalOveradableClassName("org.ejbca.core.ejb.ra.EndEntityManagementSessionBean","revokeCert"),
		new ApprovalOveradableClassName("org.ejbca.ui.web.admin.rainterface.RAInterfaceBean","unrevokeCert"),
		new ApprovalOveradableClassName("org.ejbca.ui.web.admin.rainterface.RAInterfaceBean","markForRecovery"),
		new ApprovalOveradableClassName("se.primeKey.cardPersonalization.ra.connection.ejbca.EjbcaConnection",null)
	};
    
3. Transitions that are always allowed. For some approval methods there are transitions that never require approval. For example when status for a user changes from new->inprocess, or inprocess->generated.
These rules are configured, hard coded, within the ApprovalRequest, which is the entity that knows about the transitions best. 
For example in ChangeStatusEndEntityApprovalRequest the status transitions from new->inprocess or inprocess->generated never required approval.
The code checking used by the programmer to determine if approval is required is once again ApprovalExecutorUtil. 

Checking rules
--------------
To check all these rules is simple:

int numOfApprovalsRequired = getNumOfApprovalRequired(admin, CAInfo.REQ_APPROVAL_ADDEDITENDENTITY, caid);
ChangeStatusEndEntityApprovalRequest ar = new ChangeStatusEndEntityApprovalRequest(username, data1.getStatus(), status, admin, null, numOfApprovalsRequired, data1.getCaId(), data1.getEndEntityProfileId());
if (ApprovalExecutorUtil.requireApproval(ar,NONAPPROVABLECLASSNAMES_SETUSERSTATUS)) {       		    		
    approvalsession.addApprovalRequest(admin, ar);
    throw new WaitingForApprovalException("Edit Endity Action have been added for approval by authorized adminstrators");
}  

The method ApprovalExecutorUtil.requireApproval checks first if the caller class is one of the globally excluded. Then it checks the passed in array ApprovalOveradableClassName, and last it calls the ApprovalRequest itself to see if it is a alwaysAllowedTransition (ApprovalRequest.isAlwaysAlloedTransition).

ApprovalExecutorUtil.requireApproval checks all the rules and returns true or false.

 * 
 * @version $Id$
 */
public class ApprovalExecutorUtil {
      
	private static final Logger log = Logger.getLogger(ApprovalExecutorUtil.class);
	
	/** These variables are protected to enable JUnit testing */
	protected static String globallyAllowedString = EjbcaConfiguration.getApprovalExcludedClasses();
	protected static ApprovalOveradableClassName[] globallyAllowed = null;
	
	 /** Method that checks if the request requires approval or not.
	 *
	 * 
	 * @param req the request to check
	 * @param overridableClassNames containing an array of classnamnes/mehtods that shouldn't
	 * be involved in the approvalprocess, i.e their calls to the original method
	 * shouldn't require an approval even though approvals is configured for this method. 
	 * Null means no classes should be overridable.
	 * @return true if the request requires approval, false otherwise
	 */ 
	public static boolean requireApproval(ApprovalRequest req, ApprovalOveradableClassName[] overridableClassNames) {
		if (req == null) {
			return false;
		}
	    if (log.isTraceEnabled()) {
            log.trace(">requireApproval: "+req.getClass().getName());            
        }
		boolean ret = true;
		if (req.getApprovalProfile().isApprovalRequired()) {
			ret = !isCalledByOveridableClassnames(getGloballyAllowed());
			// If we were not found in the globally allowed list, check the passed in list
			if (ret && (overridableClassNames != null)) {
				ret = !isCalledByOveridableClassnames(overridableClassNames);			
			}
			// If we were not found in any allowed list, check if it is an allowed transition
			if (ret && req.isAllowedTransition()) {
				ret = false;
			}
		} else {
			ret = false;
		}
		
        if (log.isTraceEnabled()) {
            log.trace("<requireApproval: "+ret);
        }
		return ret;
	}
		
	private static ApprovalOveradableClassName[] getGloballyAllowed() {
		if (globallyAllowed == null) {
			ArrayList<ApprovalOveradableClassName> arr = new ArrayList<ApprovalOveradableClassName>();
            StringTokenizer tokenizer = new StringTokenizer(globallyAllowedString, ",", false);
            while (tokenizer.hasMoreTokens()) {
            	String t = tokenizer.nextToken();
            	ApprovalOveradableClassName o = new ApprovalOveradableClassName(t.trim(), null);
            	arr.add(o);
            }              
            globallyAllowed = (ApprovalOveradableClassName[])arr.toArray(new ApprovalOveradableClassName[arr.size()]);
		}
		return globallyAllowed;
	}

	/** @return true if calling stack contains one of the overridableClassNames className,methodName combination. */
	private static boolean isCalledByOveridableClassnames(final ApprovalOveradableClassName[] overridableClassNames){
	    final StackTraceElement[] stackTraceElements = Thread.currentThread().getStackTrace();
	    for (final ApprovalOveradableClassName overridableClassName : overridableClassNames) {
	        if (overridableClassName.isInStackTrace(stackTraceElements)) {
	            return true;
	        }
	    }
	    return false;
	}
	   

    
}
