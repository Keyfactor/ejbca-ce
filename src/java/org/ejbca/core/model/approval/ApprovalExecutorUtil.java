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

/**
 * Util class with methods to get information about calling classes
 * Used to avoid cirkular method invocations
 * 
 * @author Philip Vendil
 *
 * @version $id$
 */
public class ApprovalExecutorUtil {

    private static final String useApprovalsOnExternalRACallsSetting = "@approval.useonextracalls@";	
	private static final boolean useApprovalsOnExternalRACalls = !useApprovalsOnExternalRACallsSetting.equalsIgnoreCase("FALSE");
	
	/**
	 * Method that checks if the current method (not this but method using this util)
	 * was call by given class.
	 *
	 * 
	 * @param className Example "AddEndEntityApprovalRequest"
	 * @return
	 */
	public static boolean isCalledByClassNameOrExtRA(String className){		
		// First check is approvals should be checked for extra calls
		boolean retval = false;
		if(useApprovalsOnExternalRACalls){
			// Do checks as usual
			retval = isCalledByClassNameHelper(className);
		}else{
			// First check that it is not called from extra
			if(isCalledByClassNameHelper("ExtRACAProcess")){
				// It is called from extra and it should not check approvals
				retval = true;
			}else{
				// Call not from extra check that it'snot from action request.
				retval = isCalledByClassNameHelper(className);
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
