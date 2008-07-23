package org.ejbca.util;

import java.rmi.RemoteException;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Date;

import org.apache.log4j.Logger;
import org.ejbca.core.ejb.ServiceLocator;
import org.ejbca.core.ejb.approval.IApprovalSessionHome;
import org.ejbca.core.ejb.approval.IApprovalSessionRemote;
import org.ejbca.core.ejb.authorization.IAuthorizationSessionHome;
import org.ejbca.core.ejb.authorization.IAuthorizationSessionRemote;
import org.ejbca.core.ejb.ca.auth.IAuthenticationSessionHome;
import org.ejbca.core.ejb.ca.auth.IAuthenticationSessionRemote;
import org.ejbca.core.ejb.ca.caadmin.ICAAdminSessionHome;
import org.ejbca.core.ejb.ca.caadmin.ICAAdminSessionRemote;
import org.ejbca.core.ejb.ca.crl.ICreateCRLSessionHome;
import org.ejbca.core.ejb.ca.crl.ICreateCRLSessionRemote;
import org.ejbca.core.ejb.ca.sign.ISignSessionHome;
import org.ejbca.core.ejb.ca.sign.ISignSessionRemote;
import org.ejbca.core.ejb.ca.store.ICertificateStoreSessionHome;
import org.ejbca.core.ejb.ca.store.ICertificateStoreSessionRemote;
import org.ejbca.core.ejb.hardtoken.IHardTokenSessionHome;
import org.ejbca.core.ejb.hardtoken.IHardTokenSessionRemote;
import org.ejbca.core.ejb.keyrecovery.IKeyRecoverySessionHome;
import org.ejbca.core.ejb.keyrecovery.IKeyRecoverySessionRemote;
import org.ejbca.core.ejb.log.ILogSessionHome;
import org.ejbca.core.ejb.log.ILogSessionRemote;
import org.ejbca.core.ejb.log.IProtectedLogSessionHome;
import org.ejbca.core.ejb.log.IProtectedLogSessionRemote;
import org.ejbca.core.ejb.ra.IUserAdminSessionHome;
import org.ejbca.core.ejb.ra.IUserAdminSessionRemote;
import org.ejbca.core.ejb.ra.raadmin.IRaAdminSessionHome;
import org.ejbca.core.ejb.ra.raadmin.IRaAdminSessionRemote;
import org.ejbca.core.ejb.services.IServiceSessionHome;
import org.ejbca.core.ejb.services.IServiceSessionRemote;
import org.ejbca.core.model.SecConst;
import org.ejbca.core.model.ca.caadmin.CAInfo;
import org.ejbca.core.model.ca.caadmin.X509CAInfo;
import org.ejbca.core.model.ca.caadmin.extendedcaservices.ExtendedCAServiceInfo;
import org.ejbca.core.model.ca.caadmin.extendedcaservices.OCSPCAServiceInfo;
import org.ejbca.core.model.ca.caadmin.extendedcaservices.XKMSCAServiceInfo;
import org.ejbca.core.model.ca.catoken.CATokenConstants;
import org.ejbca.core.model.ca.catoken.CATokenInfo;
import org.ejbca.core.model.ca.catoken.SoftCATokenInfo;
import org.ejbca.core.model.log.Admin;

public class TestTools {

	private static final Logger log = Logger.getLogger(TestTools.class);
	private static final Admin admin = new Admin(Admin.TYPE_INTERNALUSER);

	private static IApprovalSessionRemote approvalSession;
    private static IAuthenticationSessionRemote authenticationSession;
    private static IAuthorizationSessionRemote authorizationSession;
    private static ICAAdminSessionRemote caAdminSession;
    private static ICertificateStoreSessionRemote certificateStoreSession;
	private static ICreateCRLSessionRemote createCRLSession;
    private static IHardTokenSessionRemote hardTokenSession;
    private static IKeyRecoverySessionRemote keyRecoverySession;
	private static ILogSessionRemote logSession;
	private static IProtectedLogSessionRemote protectedLogSession;
    private static IRaAdminSessionRemote raAdminSession;
    private static IServiceSessionRemote serviceSession;
	private static ISignSessionRemote signSession;
    private static IUserAdminSessionRemote userAdminSession;    

	public static IApprovalSessionRemote getApprovalSession() {
		try {
			if (approvalSession == null) {
				approvalSession = ((IApprovalSessionHome) ServiceLocator.getInstance().getRemoteHome(IApprovalSessionHome.JNDI_NAME, IApprovalSessionHome.class)).create();
			}
		} catch (Exception e) {
			log.error("", e);
			return null;
		}
		return approvalSession;
	}

	public static IAuthenticationSessionRemote getAuthenticationSession() {
		try {
			if (authenticationSession == null) {
				authenticationSession = ((IAuthenticationSessionHome) ServiceLocator.getInstance().getRemoteHome(IAuthenticationSessionHome.JNDI_NAME, IAuthenticationSessionHome.class)).create();
			}
		} catch (Exception e) {
			log.error("", e);
			return null;
		}
		return authenticationSession;
	}

	public static IAuthorizationSessionRemote getAuthorizationSession() {
		try {
			if (authorizationSession == null) {
				authorizationSession = ((IAuthorizationSessionHome) ServiceLocator.getInstance().getRemoteHome(IAuthorizationSessionHome.JNDI_NAME, IAuthorizationSessionHome.class)).create();
			}
		} catch (Exception e) {
			log.error("", e);
			return null;
		}
		return authorizationSession;
	}

	public static ICAAdminSessionRemote getCAAdminSession() {
		try {
			if (caAdminSession == null) {
				caAdminSession = ((ICAAdminSessionHome) ServiceLocator.getInstance().getRemoteHome(ICAAdminSessionHome.JNDI_NAME, ICAAdminSessionHome.class)).create();
			}
		} catch (Exception e) {
			log.error("", e);
			return null;
		}
		return caAdminSession;
	}
	
	public static ICertificateStoreSessionRemote getCertificateStoreSession() {
		try {
			if (certificateStoreSession == null) {
				certificateStoreSession = ((ICertificateStoreSessionHome) ServiceLocator.getInstance().getRemoteHome(ICertificateStoreSessionHome.JNDI_NAME, ICertificateStoreSessionHome.class)).create();
			}
		} catch (Exception e) {
			log.error("", e);
			return null;
		}
		return certificateStoreSession;
	}
	
	public static ICreateCRLSessionRemote getCreateCRLSession() {
		try {
			if (createCRLSession == null) {
				createCRLSession = ((ICreateCRLSessionHome) ServiceLocator.getInstance().getRemoteHome(ICreateCRLSessionHome.JNDI_NAME, ICreateCRLSessionHome.class)).create();
			}
		} catch (Exception e) {
			log.error("", e);
			return null;
		}
		return createCRLSession;
	}
	
	public static IHardTokenSessionRemote getHardTokenSession() {
		try {
			if (hardTokenSession == null) {
				hardTokenSession = ((IHardTokenSessionHome) ServiceLocator.getInstance().getRemoteHome(IHardTokenSessionHome.JNDI_NAME, IHardTokenSessionHome.class)).create();
			}
		} catch (Exception e) {
			log.error("", e);
			return null;
		}
		return hardTokenSession;
	}
	
	public static IKeyRecoverySessionRemote getKeyRecoverySession() {
		try {
			if (keyRecoverySession == null) {
				keyRecoverySession = ((IKeyRecoverySessionHome) ServiceLocator.getInstance().getRemoteHome(IKeyRecoverySessionHome.JNDI_NAME, IKeyRecoverySessionHome.class)).create();
			}
		} catch (Exception e) {
			log.error("", e);
			return null;
		}
		return keyRecoverySession;
	}

	public static ILogSessionRemote getLogSession() {
		try {
			if (logSession == null) {
				logSession = ((ILogSessionHome) ServiceLocator.getInstance().getRemoteHome(ILogSessionHome.JNDI_NAME, ILogSessionHome.class)).create();
			}
		} catch (Exception e) {
			log.error("", e);
			return null;
		}
		return logSession;
	}

	public static IProtectedLogSessionRemote getProtectedLogSession() {
		try {
			if (protectedLogSession == null) {
				protectedLogSession = ((IProtectedLogSessionHome) ServiceLocator.getInstance().getRemoteHome(IProtectedLogSessionHome.JNDI_NAME, IProtectedLogSessionHome.class)).create();
			}
		} catch (Exception e) {
			log.error("", e);
			return null;
		}
		return protectedLogSession;
	}

	public static IRaAdminSessionRemote getRaAdminSession() {
		try {
			if (raAdminSession == null) {
				raAdminSession = ((IRaAdminSessionHome) ServiceLocator.getInstance().getRemoteHome(IRaAdminSessionHome.JNDI_NAME, IRaAdminSessionHome.class)).create();
			}
		} catch (Exception e) {
			log.error("", e);
			return null;
		}
		return raAdminSession;
	}

	public static ISignSessionRemote getSignSession() {
		try {
			if (signSession == null) {
				signSession = ((ISignSessionHome) ServiceLocator.getInstance().getRemoteHome(ISignSessionHome.JNDI_NAME, ISignSessionHome.class)).create();
			}
		} catch (Exception e) {
			log.error("", e);
			return null;
		}
		return signSession;
	}

	public static IServiceSessionRemote getServiceSession() {
		try {
			if (serviceSession == null) {
				serviceSession = ((IServiceSessionHome) ServiceLocator.getInstance().getRemoteHome(IServiceSessionHome.JNDI_NAME, IServiceSessionHome.class)).create();
			}
		} catch (Exception e) {
			log.error("", e);
			return null;
		}
		return serviceSession;
	}

	public static IUserAdminSessionRemote getUserAdminSession() {
		try {
			if (userAdminSession == null) {
				userAdminSession = ((IUserAdminSessionHome) ServiceLocator.getInstance().getRemoteHome(IUserAdminSessionHome.JNDI_NAME, IUserAdminSessionHome.class)).create();
			}
		} catch (Exception e) {
			log.error("", e);
			return null;
		}
		return userAdminSession;
	}


	/**
	 * Makes sure the Test CA with subject DN "CN=TEST" exists.
	 * 
	 * @return true if successful
	 */
	public static boolean createTestCA() {
		return createTestCA("TEST");
	}

	/**
	 * Makes sure the Test CA exists.
	 * 
	 * @return true if successful
	 */
	public static boolean createTestCA(String caName) {
        log.debug(">createTestCA");
		// Search for requested CA
        try {
			CAInfo caInfo = getCAAdminSession().getCAInfo(admin, caName);
			if (caInfo != null) {
				return true;
			}
		} catch (RemoteException e) {
			log.error("", e);
			return false;
		}
		// Create request CA, if neccesary
        SoftCATokenInfo catokeninfo = new SoftCATokenInfo();
        catokeninfo.setSignKeySpec("1024");
        catokeninfo.setEncKeySpec("1024");
        catokeninfo.setSignKeyAlgorithm(SoftCATokenInfo.KEYALGORITHM_RSA);
        catokeninfo.setEncKeyAlgorithm(SoftCATokenInfo.KEYALGORITHM_RSA);
        catokeninfo.setSignatureAlgorithm(CATokenInfo.SIGALG_SHA1_WITH_RSA);
        catokeninfo.setEncryptionAlgorithm(CATokenInfo.SIGALG_SHA1_WITH_RSA);
        // Create and active OSCP CA Service.
        ArrayList extendedcaservices = new ArrayList();
        extendedcaservices.add(new OCSPCAServiceInfo(ExtendedCAServiceInfo.STATUS_ACTIVE,
                "CN=OCSPSignerCertificate, " + "CN="+caName,
                "",
                "1024",
                CATokenConstants.KEYALGORITHM_RSA));
        extendedcaservices.add(new XKMSCAServiceInfo(ExtendedCAServiceInfo.STATUS_ACTIVE,
                "CN=XKMSCertificate, " + "CN="+caName,
                "",
                "1024",
                CATokenConstants.KEYALGORITHM_RSA));
        /*
        extendedcaservices.add(new CmsCAServiceInfo(ExtendedCAServiceInfo.STATUS_ACTIVE,
        		"CN=CMSCertificate, " + "CN="+caName,
        		"",
        		"1024",
                CATokenConstants.KEYALGORITHM_RSA));
        */
        X509CAInfo cainfo = new X509CAInfo("CN="+caName,
                caName, SecConst.CA_ACTIVE, new Date(),
                "", SecConst.CERTPROFILE_FIXED_ROOTCA,
                3650,
                null, // Expiretime
                CAInfo.CATYPE_X509,
                CAInfo.SELFSIGNED,
                (Collection) null,
                catokeninfo,
                "JUnit RSA CA",
                -1, null,
                null, // PolicyId
                24, // CRLPeriod
                0, // CRLIssueInterval
                10, // CRLOverlapTime
                10, // Delta CRL period
                new ArrayList(),
                true, // Authority Key Identifier
                false, // Authority Key Identifier Critical
                true, // CRL Number
                false, // CRL Number Critical
                null, // defaultcrldistpoint 
                null, // defaultcrlissuer 
                null, // defaultocsplocator
                null, // defaultfreshestcrl
                true, // Finish User
                extendedcaservices,
                false, // use default utf8 settings
                new ArrayList(), // Approvals Settings
                1, // Number of Req approvals
                false, // Use UTF8 subject DN by default
        		true, // Use LDAP DN order by default
        		false, // Use CRL Distribution Point on CRL
        		false,  // CRL Distribution Point on CRL critical
        		true);

        try {
        	getCAAdminSession().createCA(admin, cainfo);
		} catch (Exception e) {
			log.error("", e);
			return false;
		}
        log.debug("<createTestCA");
		return true;
	}


	/**
	 * Removes the Test-CA with subject DN "CN=TEST" if it exists.
	 * 
	 * @return true if successful
	 */
	public static boolean removeTestCA() {
		return removeTestCA("TEST");
	}

	/**
	 * Removes the Test-CA if it exists.
	 * 
	 * @return true if successful
	 */
	public static boolean removeTestCA(String caName) {
		// Search for requested CA
        try {
			CAInfo caInfo = getCAAdminSession().getCAInfo(admin, caName);
			if (caInfo == null) {
				return true;
			}
			getCAAdminSession().removeCA(admin, ("CN=" + caName).hashCode());
		} catch (Exception e) {
			log.error("", e);
			return false;
		}
		return true;
	}

	/**
	 * @return the caid of a CA with subject DN "CN=TEST"
	 */
	public static int getTestCAId() {
		return getTestCAId("TEST");
	}

	/**
	 * @return the caid of a test CA with subject DN CN=caName
	 */
	public static int getTestCAId(String caName) {
		return ("CN=" + caName).hashCode();
	}
}
