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

/**
 * @version $Id$
 */
public class ApprovalJunitHelper {

	public static class JunitApprovalExecutorUtil1 extends ApprovalExecutorUtil {
	    
		public static void init() {
			ApprovalExecutorUtil.globallyAllowedString = ApprovalExecutorUtilTest.class.getName();
			ApprovalExecutorUtil.globallyAllowed = null;
			
		}
	}
	public static class JunitApprovalExecutorUtil2 extends ApprovalExecutorUtil {
	      
		public static void init() {
			ApprovalExecutorUtil.globallyAllowedString = "foo.base.Foo,".concat(ApprovalExecutorUtilTest.class.getName()).concat(", foo.bar.Bar");
			ApprovalExecutorUtil.globallyAllowed = null;
			
		}
	}
	public static class JunitApprovalExecutorUtil3 extends ApprovalExecutorUtil {
	      
		public static void init() {
			ApprovalExecutorUtil.globallyAllowedString = "foo.base.Foo, foo.bar.Bar";
			ApprovalExecutorUtil.globallyAllowed = null;
			
		}
	}

}
