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

	/**
	 * Method that checks if the current method (not this but method using this util)
	 * was call by given class.
	 *
	 * 
	 * @param className Example "AddEndEntityApprovalRequest"
	 * @return
	 */
	public static boolean isCalledByClassName(String className){		
		
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
