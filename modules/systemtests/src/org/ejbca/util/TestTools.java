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

import java.rmi.RemoteException;
import java.security.cert.Certificate;
import java.security.cert.CertificateEncodingException;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Date;
import java.util.Iterator;
import java.util.Random;

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
import org.ejbca.core.ejb.ca.publisher.IPublisherQueueSessionHome;
import org.ejbca.core.ejb.ca.publisher.IPublisherQueueSessionRemote;
import org.ejbca.core.ejb.ca.publisher.IPublisherSessionHome;
import org.ejbca.core.ejb.ca.publisher.IPublisherSessionRemote;
import org.ejbca.core.ejb.ca.sign.ISignSessionHome;
import org.ejbca.core.ejb.ca.sign.ISignSessionRemote;
import org.ejbca.core.ejb.ca.store.ICertificateStoreSessionHome;
import org.ejbca.core.ejb.ca.store.ICertificateStoreSessionRemote;
import org.ejbca.core.ejb.config.IConfigurationSessionHome;
import org.ejbca.core.ejb.hardtoken.IHardTokenSessionHome;
import org.ejbca.core.ejb.hardtoken.IHardTokenSessionRemote;
import org.ejbca.core.ejb.keyrecovery.IKeyRecoverySessionHome;
import org.ejbca.core.ejb.keyrecovery.IKeyRecoverySessionRemote;
import org.ejbca.core.ejb.log.ILogSessionHome;
import org.ejbca.core.ejb.log.ILogSessionRemote;
import org.ejbca.core.ejb.log.IProtectedLogSessionHome;
import org.ejbca.core.ejb.log.IProtectedLogSessionRemote;
import org.ejbca.core.ejb.protect.TableProtectSessionHome;
import org.ejbca.core.ejb.protect.TableProtectSessionRemote;
import org.ejbca.core.ejb.ra.ICertificateRequestSessionHome;
import org.ejbca.core.ejb.ra.ICertificateRequestSessionRemote;
import org.ejbca.core.ejb.ra.IUserAdminSessionHome;
import org.ejbca.core.ejb.ra.IUserAdminSessionRemote;
import org.ejbca.core.ejb.ra.raadmin.IRaAdminSessionHome;
import org.ejbca.core.ejb.ra.raadmin.IRaAdminSessionRemote;
import org.ejbca.core.ejb.ra.userdatasource.IUserDataSourceSessionHome;
import org.ejbca.core.ejb.ra.userdatasource.IUserDataSourceSessionRemote;
import org.ejbca.core.ejb.services.IServiceSessionHome;
import org.ejbca.core.ejb.services.IServiceSessionRemote;
import org.ejbca.core.ejb.upgrade.IConfigurationSessionRemote;
import org.ejbca.core.model.AlgorithmConstants;
import org.ejbca.core.model.SecConst;
import org.ejbca.core.model.authorization.AdminGroupExistsException;
import org.ejbca.core.model.ca.caadmin.CAInfo;
import org.ejbca.core.model.ca.caadmin.X509CAInfo;
import org.ejbca.core.model.ca.caadmin.extendedcaservices.ExtendedCAServiceInfo;
import org.ejbca.core.model.ca.caadmin.extendedcaservices.OCSPCAServiceInfo;
import org.ejbca.core.model.ca.caadmin.extendedcaservices.XKMSCAServiceInfo;
import org.ejbca.core.model.ca.catoken.SoftCATokenInfo;
import org.ejbca.core.model.log.Admin;

/** Common glue code that can be called from all JUnit tests to make it easier to call remote beans etc.
 * 
 * @version $Id$
 */
public class TestTools {

	private static final Logger log = Logger.getLogger(TestTools.class);
	private static final Admin admin = new Admin(Admin.TYPE_INTERNALUSER);
	public static final String defaultSuperAdminCN = "SuperAdmin";

	private static IApprovalSessionRemote approvalSession;
    private static IAuthenticationSessionRemote authenticationSession;
    private static IAuthorizationSessionRemote authorizationSession;
    private static ICAAdminSessionRemote caAdminSession;
    private static ICertificateStoreSessionRemote certificateStoreSession;
    private static ICertificateRequestSessionRemote certificateRequestSession;
    private static IConfigurationSessionRemote configurationSession;
	private static ICreateCRLSessionRemote createCRLSession;
    private static IHardTokenSessionRemote hardTokenSession;
    private static IKeyRecoverySessionRemote keyRecoverySession;
	private static ILogSessionRemote logSession;
	private static IProtectedLogSessionRemote protectedLogSession;
    private static IRaAdminSessionRemote raAdminSession;
    private static IServiceSessionRemote serviceSession;
	private static ISignSessionRemote signSession;
    private static IUserAdminSessionRemote userAdminSession;
    private static IPublisherQueueSessionRemote publisherQueueSession;
    private static IPublisherSessionRemote publisherSession;
    private static TableProtectSessionRemote tableProtectSession;
    private static IUserDataSourceSessionRemote userDataSourceSession;

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
	
	public static IConfigurationSessionRemote getConfigurationSession() {
		try {
			if (configurationSession == null) {
				configurationSession = ((IConfigurationSessionHome) ServiceLocator.getInstance().getRemoteHome(IConfigurationSessionHome.JNDI_NAME, IConfigurationSessionHome.class)).create();
			}
		} catch (Exception e) {
			log.error("", e);
			return null;
		}
		return configurationSession;
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
	
	public static ICertificateRequestSessionRemote getCertificateRequestSession() {
		try {
			if (certificateRequestSession == null) {
				certificateRequestSession = ((ICertificateRequestSessionHome) ServiceLocator.getInstance().getRemoteHome(ICertificateRequestSessionHome.JNDI_NAME, ICertificateRequestSessionHome.class)).create();
			}
		} catch (Exception e) {
			log.error("", e);
			return null;
		}
		return certificateRequestSession;
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

	public static IPublisherQueueSessionRemote getPublisherQueueSession() {
		try {
			if (publisherQueueSession == null) {
				publisherQueueSession = ((IPublisherQueueSessionHome) ServiceLocator.getInstance().getRemoteHome(IPublisherQueueSessionHome.JNDI_NAME, IPublisherQueueSessionHome.class)).create();
			}
		} catch (Exception e) {
			log.error("", e);
			return null;
		}
		return publisherQueueSession;
	}

	public static IPublisherSessionRemote getPublisherSession() {
		try {
			if (publisherSession == null) {
				publisherSession = ((IPublisherSessionHome) ServiceLocator.getInstance().getRemoteHome(IPublisherSessionHome.JNDI_NAME, IPublisherSessionHome.class)).create();
			}
		} catch (Exception e) {
			log.error("", e);
			return null;
		}
		return publisherSession;
	}

	public static TableProtectSessionRemote getTableProtectSession() {
		try {
			if (tableProtectSession == null) {
				tableProtectSession = ((TableProtectSessionHome) ServiceLocator.getInstance().getRemoteHome(TableProtectSessionHome.JNDI_NAME, TableProtectSessionHome.class)).create();
			}
		} catch (Exception e) {
			log.error("", e);
			return null;
		}
		return tableProtectSession;
	}

	public static IUserDataSourceSessionRemote getUserDataSourceSession() {
		try {
			if (userDataSourceSession == null) {
				userDataSourceSession = ((IUserDataSourceSessionHome) ServiceLocator.getInstance().getRemoteHome(IUserDataSourceSessionHome.JNDI_NAME, IUserDataSourceSessionHome.class)).create();
			}
		} catch (Exception e) {
			log.error("", e);
			return null;
		}
		return userDataSourceSession;
	}

	/**
	 * Makes sure the Test CA exists.
	 * 
	 * @return true if successful
	 */
	public static boolean createTestCA() {
		return createTestCA(getTestCAName(), 1024);
	}

	/**
	 * Makes sure the Test CA exists.
	 * 
	 * @return true if successful
	 */
	public static boolean createTestCA(int keyStrength) {
		return createTestCA(getTestCAName(), keyStrength);
	}

	/**
	 * Makes sure the Test CA exists.
	 * 
	 * @return true if successful
	 */
	public static boolean createTestCA(String caName) {
		return createTestCA(caName, 1024);
	}

	/**
	 * Makes sure the Test CA exists.
	 * 
	 * @return true if successful
	 */
	public static boolean createTestCA(String caName, int keyStrength) {
        log.trace(">createTestCA");
    	try {
			getAuthorizationSession().initialize(admin, ("CN="+caName).hashCode(), TestTools.defaultSuperAdminCN);
		} catch (RemoteException e) {
			log.error("",e);
		} catch (AdminGroupExistsException e) {
			log.error("",e);
		}
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
		// Create request CA, if necessary
        SoftCATokenInfo catokeninfo = new SoftCATokenInfo();
        catokeninfo.setSignKeySpec(""+keyStrength);
        catokeninfo.setEncKeySpec(""+keyStrength);
        catokeninfo.setSignKeyAlgorithm(AlgorithmConstants.KEYALGORITHM_RSA);
        catokeninfo.setEncKeyAlgorithm(AlgorithmConstants.KEYALGORITHM_RSA);
        catokeninfo.setSignatureAlgorithm(AlgorithmConstants.SIGALG_SHA1_WITH_RSA);
        catokeninfo.setEncryptionAlgorithm(AlgorithmConstants.SIGALG_SHA1_WITH_RSA);
        // Create and active OSCP CA Service.
        ArrayList extendedcaservices = new ArrayList();
        extendedcaservices.add(new OCSPCAServiceInfo(ExtendedCAServiceInfo.STATUS_ACTIVE));
        extendedcaservices.add(new XKMSCAServiceInfo(ExtendedCAServiceInfo.STATUS_ACTIVE,
                "CN=XKMSCertificate, " + "CN="+caName,
                "",
                ""+keyStrength,
                AlgorithmConstants.KEYALGORITHM_RSA));
        /*
        extendedcaservices.add(new CmsCAServiceInfo(ExtendedCAServiceInfo.STATUS_ACTIVE,
        		"CN=CMSCertificate, " + "CN="+caName,
        		"",
        		""+keyStrength,
                AlgorithmConstants.KEYALGORITHM_RSA));
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
        		true,
                true, // isDoEnforceUniquePublicKeys
                true, // isDoEnforceUniqueDistinguishedName
                false, // isDoEnforceUniqueSubjectDNSerialnumber
                true // useCertReqHistory
        		);

        try {
        	getCAAdminSession().createCA(admin, cainfo);
		} catch (Exception e) {
			log.error("", e);
			return false;
		}
        CAInfo info;
		try {
			info = getCAAdminSession().getCAInfo(admin, caName);
		} catch (RemoteException e) {
			log.error("", e);
			return false;
		}
        X509Certificate cert = (X509Certificate) info.getCertificateChain().iterator().next();
        if (!cert.getSubjectDN().toString().equals("CN="+caName)) {
        	log.error("Error in created CA certificate!");
			return false;
        }
        if (!info.getSubjectDN().equals("CN="+caName)) {
        	log.error("Creating CA failed!");
			return false;
        }
        try {
			if (getCertificateStoreSession().findCertificateByFingerprint(admin, CertTools.getCertFingerprintAsString(cert.getEncoded())) == null) {
	        	log.error("CA certificate not available in database!!");
	        	return false;
			}
		} catch (CertificateEncodingException e) {
        	log.error("", e);
			return false;
		} catch (RemoteException e) {
        	log.error("", e);
			return false;
		}
        log.trace("<createTestCA");
		return true;
	}


	/**
	 * Removes the Test-CA if it exists.
	 * 
	 * @return true if successful
	 */
	public static boolean removeTestCA() {
		return removeTestCA(getTestCAName());
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
	 * @return the caid of the test CA
	 */
	public static int getTestCAId() {
		return getTestCAId(getTestCAName());
	}

	/**
	 * @return the caid of a test CA with subject DN CN=caName
	 */
	public static int getTestCAId(String caName) {
		return ("CN=" + caName).hashCode();
	}

	/**
	 * @return the name of the test CA
	 */
	public static String getTestCAName() {
		return "TEST";
	}

	/**
	 * @return the CA certificate
	 */
	public static Certificate getTestCACert() {
		return getTestCACert(getTestCAName());
	}
	
	/**
	 * @return the CA certificate
	 */
	public static Certificate getTestCACert(String caName) {
		Certificate cacert = null;
		try {
	        CAInfo cainfo = getCAAdminSession().getCAInfo(admin, getTestCAId(caName));
	        Collection certs = cainfo.getCertificateChain();
	        if (certs.size() > 0) {
	            Iterator certiter = certs.iterator();
	            cacert = (X509Certificate) certiter.next();
	        } else {
	            log.error("NO CACERT for caid " + getTestCAId(caName));
	        }
		} catch (RemoteException e) {
			log.error("", e);
		}
		return cacert;
	}
	
    public static final String genRandomUserName() {
        // Generate random user
        Random rand = new Random(new Date().getTime() + 4711);
        String username = "";
        for (int i = 0; i < 6; i++) {
            int randint = rand.nextInt(9);
            username += (new Integer(randint)).toString();
        }
        log.debug("Generated random username: username =" + username);
        return username;
    } // genRandomUserName

    public static final String genRandomPwd() {
        // Generate random password
        Random rand = new Random(new Date().getTime() + 4812);
        String password = "";
        for (int i = 0; i < 8; i++) {
            int randint = rand.nextInt(9);
            password += (new Integer(randint)).toString();
        }
        log.debug("Generated random pwd: password=" + password);
        return password;
    } // genRandomPwd

}
