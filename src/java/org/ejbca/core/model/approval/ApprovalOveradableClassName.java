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

import org.apache.log4j.Logger;

/**
 * Class used in constants for approvalable methods indicating calling classes/methods
 * that don't need to go through approvals
 * 
 * Contains the full classpath and method na,e
 * 
 * @author Philip Vendil
 * $Id$
 */
public class ApprovalOveradableClassName {
	
	private static final Logger log = Logger.getLogger(ApprovalOveradableClassName.class);
	
	String className = null;
	String methodName = null;
	
	/**
	 * 
	 * @param className The full name with packages
	 * @param methodName the method name/ can be null indicating all methods
	 */
	public ApprovalOveradableClassName(String className, String methodName) {
		super();
		this.className = className;
		this.methodName = methodName;
	}

	/**
	 * @return The full name with packages
	 */
	
	public String getClassName() {
		return className;
	}

	public String getMethodName() {
		return methodName;
	}
	
	/**
	 * Method that checks if the current classname / method is in the stacktrace
	 * @param traces
	 * @return if the class.method exists in trace
	 */
	public boolean isInStackTrace(StackTraceElement[] traces){
		
		boolean retval = false;
		for(int i=0;i<traces.length;i++){
		    if (log.isDebugEnabled()) {
		    	log.debug("Compare " + className + "." + methodName + " with " + traces[i].getClassName() + "." +traces[i].getMethodName() );           
	        }			
			if(traces[i].getClassName().equals(className)){
				if(methodName != null){
					retval = traces[i].getMethodName().equals(methodName);
					if(retval == true){
						break;
					}
				}else{
					retval = true;
					break;					
				}
			}
		}
		
		
	    if (log.isDebugEnabled()) {
	    	log.debug("Result " + retval);           
        }	
		
		return retval;
	}

}
