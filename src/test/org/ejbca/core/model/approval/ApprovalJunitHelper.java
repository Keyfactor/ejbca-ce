package org.ejbca.core.model.approval;

import org.ejbca.core.model.approval.ApprovalExecutorUtil;

public class ApprovalJunitHelper {

	public static class JunitApprovalExecutorUtil1 extends ApprovalExecutorUtil {
	    
		public static void init() {
			ApprovalExecutorUtil.globallyAllowedString = "org.ejbca.core.model.approval.TestApprovalExecutorUtil";
			ApprovalExecutorUtil.globallyAllowed = null;
			
		}
	}
	public static class JunitApprovalExecutorUtil2 extends ApprovalExecutorUtil {
	      
		public static void init() {
			ApprovalExecutorUtil.globallyAllowedString = "foo.base.Foo,org.ejbca.core.model.approval.TestApprovalExecutorUtil, foo.bar.Bar";
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
