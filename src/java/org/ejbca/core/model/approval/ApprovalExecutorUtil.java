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
package org.ejbca.core.model.approval;

import org.apache.log4j.Logger;

/**
 * Util class with methods to get information about calling classes
 * Used to avoid cirkular method invocations
 * 
 * @author Philip Vendil
 *
 * @version $id$
 */
public class ApprovalExecutorUtil {
      
	private static final Logger log = Logger.getLogger(ApprovalOveradableClassName.class);
	
    private static final String useApprovalsOnExternalRACallsSetting = "@approval.useonextracalls@";	
	private static final boolean useApprovalsOnExternalRACalls = !useApprovalsOnExternalRACallsSetting.equalsIgnoreCase("FALSE");
			
	/**
	 * Method that checks if the current method (not this but method using this util)
	 * was called by given class.
	 *
	 * 
	 * @param className Example "AddEndEntityApprovalRequest"
	 * @param overridableClassNames containing a separated ';' string of classnamnes that shouldn't
	 * be involved in the approvalprocess, i.e their calls to the original method
	 * shouldn't require an approval even though approvals is configured for this method. 
	 * Null means no classes should be overridable.
	 * @return true is the method was called by the given class, false otherwise
	 */
	public static boolean isCalledByClassNameOrExtRA(String className, ApprovalOveradableClassName[] overridableClassNames){		
	    if (log.isDebugEnabled()) {
            log.debug(">isCalledByClassNameOrExtRA: "+className);            
        }
		// First check is approvals should be checked for extra calls
		boolean retval = false;
		if(useApprovalsOnExternalRACalls){
			// Do checks as usual
			retval = isCalledByClassNameHelper(className) || isCalledByOveridableClassnames(overridableClassNames);
		}else{
			// First check that it is not called from extra
			if(isCalledByClassNameHelper("ExtRACAProcess")){
				// It is called from extra and it should not check approvals
				retval = true;
			}else{
				// Call not from extra check that it'snot from action request.
				retval = isCalledByClassNameHelper(className) || isCalledByOveridableClassnames(overridableClassNames);
			}
		  
		}		
        if (log.isDebugEnabled()) {
            log.debug("<isCalledByClassNameOrExtRA: "+retval);
        }
		return retval;
	}
	
	private static boolean isCalledByOveridableClassnames(ApprovalOveradableClassName[] overridableClassNames){		
		boolean retval = false;
		try{
			throw new Exception();
		}catch(Exception e){
			if(overridableClassNames != null){
				Throwable next = e;
				while(next != null){
				  for(int j=0;j< overridableClassNames.length;j++){
					retval = overridableClassNames[j].isInStackTrace(e.getStackTrace());
					if(retval == true){
						break;
					}
				  }
				  if(retval == true){
						break;
				  }
				  next = e.getCause();
				}
			}
		}
		
		return retval;
	}
	
	private static boolean isCalledByClassNameHelper(String className){		
		boolean retval = false;
		try{
			throw new Exception();
		}catch(Exception e){
			className = "." + className;			
			StackTraceElement[] traces = e.getStackTrace();
			for(int i=0;i<traces.length;i++){
				if(traces[i].getClassName().endsWith(className)){
					retval = true;
					break;
				}
			}			
		}
		
		return retval;
	}
	
}
