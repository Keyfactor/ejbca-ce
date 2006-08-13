package se.anatom.ejbca.approval;

import org.ejbca.core.model.approval.ApprovalExecutorUtil;

public class ApprovalJunitHelper {

	public static class JunitApprovalExecutorUtil1 extends ApprovalExecutorUtil {
	    
		public static void init() {
			ApprovalExecutorUtil.globallyAllowedString = "se.anatom.ejbca.approval.TestApprovalExecutorUtil";
			ApprovalExecutorUtil.globallyAllowed = null;
			
		}
	}
	public static class JunitApprovalExecutorUtil2 extends ApprovalExecutorUtil {
	      
		public static void init() {
			ApprovalExecutorUtil.globallyAllowedString = "foo.base.Foo,se.anatom.ejbca.approval.TestApprovalExecutorUtil, foo.bar.Bar";
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
