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
 
package org.ejbca.ui.cli;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.security.KeyFactory;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;

import org.apache.log4j.Logger;
import org.ejbca.core.ejb.ServiceLocator;
import org.ejbca.core.ejb.authorization.IAuthorizationSessionHome;
import org.ejbca.core.ejb.authorization.IAuthorizationSessionRemote;
import org.ejbca.core.ejb.ca.auth.IAuthenticationSessionHome;
import org.ejbca.core.ejb.ca.auth.IAuthenticationSessionRemote;
import org.ejbca.core.ejb.ca.caadmin.ICAAdminSessionHome;
import org.ejbca.core.ejb.ca.caadmin.ICAAdminSessionRemote;
import org.ejbca.core.ejb.ca.crl.ICreateCRLSessionHome;
import org.ejbca.core.ejb.ca.crl.ICreateCRLSessionRemote;
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
import org.ejbca.core.ejb.log.IProtectedLogSessionHome;
import org.ejbca.core.ejb.log.IProtectedLogSessionRemote;
import org.ejbca.core.ejb.ra.IUserAdminSessionHome;
import org.ejbca.core.ejb.ra.IUserAdminSessionRemote;
import org.ejbca.core.ejb.ra.raadmin.IRaAdminSessionHome;
import org.ejbca.core.ejb.ra.raadmin.IRaAdminSessionRemote;
import org.ejbca.core.ejb.ra.userdatasource.IUserDataSourceSessionHome;
import org.ejbca.core.ejb.ra.userdatasource.IUserDataSourceSessionRemote;
import org.ejbca.core.ejb.upgrade.IConfigurationSessionRemote;
import org.ejbca.core.ejb.upgrade.IUpgradeSessionHome;
import org.ejbca.core.ejb.upgrade.IUpgradeSessionRemote;
import org.ejbca.core.model.log.Admin;
import org.ejbca.util.Base64;
import org.ejbca.util.CertTools;
import org.ejbca.util.keystore.KeyTools;

/**
 * Base for Commands, contains useful functions
 *
 * @version $Id$
 */
public abstract class BaseCommand implements CliCommandPlugin {

    private static Logger baseLog = Logger.getLogger(BaseCommand.class);
    private static Logger log = null;

    /** Not static since different object should go to different session beans concurrently */
    private IUserAdminSessionRemote userAdminSession = null;
    private IRaAdminSessionRemote raAdminSession = null;
    private ICAAdminSessionRemote caAdminSession = null;
    private ICertificateStoreSessionRemote certificateStoreSession = null;
    private IPublisherSessionRemote publisherSession = null;
	private IProtectedLogSessionRemote protectedLogSession = null;
    private IUpgradeSessionRemote upgradeSession = null;
    private ICreateCRLSessionRemote createCRLSession = null;
    private IAuthorizationSessionRemote authorizationSession = null;
    private IHardTokenSessionRemote hardTokenSession = null;
    private IKeyRecoverySessionRemote keyRecoverySession = null;
    private IUserDataSourceSessionRemote userDataSourceSession = null;
    private ISignSessionRemote signSession = null;
    private IConfigurationSessionRemote configurationSession = null;
	private IAuthenticationSessionRemote authenticationSession = null;
    
	private Admin admin = new Admin(Admin.TYPE_CACOMMANDLINE_USER, "cli");
    
    protected Logger getLogger() {
    	if (log == null) {
    		log = Logger.getLogger(this.getClass());
    	}
    	return log;
    }
    
    protected Admin getAdmin() { return admin; }
    
    protected String getCommand() {
    	return (getMainCommand()!=null?getMainCommand() + " ":"") + getSubCommand();
    }
    
    /**
     *@return a reference to a CAAdminSessionBean
     */
    protected ICAAdminSessionRemote getCAAdminSession() {
    	baseLog.trace(">getCAAdminSession()");
		try {
			if (caAdminSession == null) {
				caAdminSession = ((ICAAdminSessionHome) ServiceLocator.getInstance().getRemoteHome(
						ICAAdminSessionHome.JNDI_NAME, ICAAdminSessionHome.class)).create();
			}
		} catch (Exception e) {
			baseLog.error("", e);
			throw new RuntimeException(e);
		}
		baseLog.trace("<getCAAdminSession()");
        return caAdminSession;
     }

    /**
     *@return a reference to a ProtectedLogSessionBean
     */
    protected IProtectedLogSessionRemote getProtectedLogSession() {
    	baseLog.trace(">getProtectedLogSession()");
		try {
			if (protectedLogSession == null) {
				protectedLogSession = ((IProtectedLogSessionHome) ServiceLocator.getInstance().getRemoteHome(
						IProtectedLogSessionHome.JNDI_NAME, IProtectedLogSessionHome.class)).create();
			}
		} catch (Exception e) {
			baseLog.error("", e);
			throw new RuntimeException(e);
		}
		baseLog.trace("<getProtectedLogSession()");
        return protectedLogSession;
     }

    /**
     *@return a reference to a CertificateStoreSessionBean
     */
    protected ICertificateStoreSessionRemote getCertificateStoreSession() {
    	baseLog.trace(">getCertificateStoreSession()");
		try {
			if (certificateStoreSession == null) {
				certificateStoreSession = ((ICertificateStoreSessionHome) ServiceLocator.getInstance().getRemoteHome(
						ICertificateStoreSessionHome.JNDI_NAME, ICertificateStoreSessionHome.class)).create();
			}
		} catch (Exception e) {
			baseLog.error("", e);
			throw new RuntimeException(e);
		}
		baseLog.trace("<getCertificateStoreSession()");
        return certificateStoreSession;
     }
    
    /**
     *@return a reference to a PublisherSessionBean
     */
    protected IPublisherSessionRemote getPublisherSession() {
    	baseLog.trace(">getPublisherSession()");
		try {
			if (publisherSession == null) {
				publisherSession = ((IPublisherSessionHome) ServiceLocator.getInstance().getRemoteHome(
						IPublisherSessionHome.JNDI_NAME, IPublisherSessionHome.class)).create();
			}
		} catch (Exception e) {
			baseLog.error("", e);
			throw new RuntimeException(e);
		}
		baseLog.trace("<getPublisherSession()");
        return publisherSession;
     }

    /**
     *@return a reference to a UserAdminSessionBean
     */
    protected IUserAdminSessionRemote getUserAdminSession() {
    	baseLog.trace(">getUserAdminSession()");
		try {
			if (userAdminSession == null) {
				userAdminSession = ((IUserAdminSessionHome) ServiceLocator.getInstance().getRemoteHome(
						IUserAdminSessionHome.JNDI_NAME, IUserAdminSessionHome.class)).create();
			}
		} catch (Exception e) {
			baseLog.error("", e);
			throw new RuntimeException(e);
		}
		baseLog.trace("<getUserAdminSession()");
        return userAdminSession;
    }
    
    /**
     *@return a reference to a RaAdminSessionBean
     */
    protected IRaAdminSessionRemote getRaAdminSession() {
    	baseLog.trace(">getRaAdminSession()");
        //administrator = new Admin(Admin.TYPE_RA_USER);
		try {
			if (raAdminSession == null) {
				raAdminSession = ((IRaAdminSessionHome) ServiceLocator.getInstance().getRemoteHome(
						IRaAdminSessionHome.JNDI_NAME, IRaAdminSessionHome.class)).create();
			}
		} catch (Exception e) {
			baseLog.error("", e);
			throw new RuntimeException(e);
		}
		baseLog.trace("<getRaAdminSession()");
        return  raAdminSession;
    }    

    /**
     *@return a reference to a UpgradeSessionBean
     */
    protected IUpgradeSessionRemote getUpgradeSession() {
    	baseLog.trace(">getUpgradeSession()");
		try {
			if (upgradeSession == null) {
				upgradeSession = ((IUpgradeSessionHome) ServiceLocator.getInstance().getRemoteHome(
						IUpgradeSessionHome.JNDI_NAME, IUpgradeSessionHome.class)).create();
			}
		} catch (Exception e) {
			baseLog.error("", e);
			throw new RuntimeException(e);
		}
		baseLog.trace("<getUpgradeSession()");
        return upgradeSession;
     }
    
    /**
     *@return a reference to a CreateCRLSessionBean
     */
    protected ICreateCRLSessionRemote getCreateCRLSession() {
    	baseLog.trace(">getCreateCRLSession()");
		try {
			if (createCRLSession == null) {
				createCRLSession = ((ICreateCRLSessionHome) ServiceLocator.getInstance().getRemoteHome(
						ICreateCRLSessionHome.JNDI_NAME, ICreateCRLSessionHome.class)).create();
			}
		} catch (Exception e) {
			baseLog.error("", e);
			throw new RuntimeException(e);
		}
		baseLog.trace("<getCreateCRLSession()");
        return createCRLSession;
     }

    /**
     *@return a reference to a AuthorizationSessionBean
     */
    protected IAuthorizationSessionRemote getAuthorizationSession() {
    	baseLog.trace(">getAuthorizationSession()");
		try {
			if (authorizationSession == null) {
				authorizationSession = ((IAuthorizationSessionHome) ServiceLocator.getInstance().getRemoteHome(
						IAuthorizationSessionHome.JNDI_NAME, IAuthorizationSessionHome.class)).create();
			}
		} catch (Exception e) {
			baseLog.error("", e);
			throw new RuntimeException(e);
		}
		baseLog.trace("<getAuthorizationSession()");
        return authorizationSession;
     }

    /**
     *@return a reference to a HardTokenSessionBean
     */
    protected IHardTokenSessionRemote getHardTokenSession() {
    	baseLog.trace(">getHardTokenSession()");
		try {
			if (hardTokenSession == null) {
				hardTokenSession = ((IHardTokenSessionHome) ServiceLocator.getInstance().getRemoteHome(
						IHardTokenSessionHome.JNDI_NAME, IHardTokenSessionHome.class)).create();
			}
		} catch (Exception e) {
			baseLog.error("", e);
			throw new RuntimeException(e);
		}
		baseLog.trace("<getHardTokenSession()");
        return hardTokenSession;
     }

    /**
     *@return a reference to a KeyRecoverySessionBean
     */
    protected IKeyRecoverySessionRemote getKeyRecoverySession() {
    	baseLog.trace(">getKeyRecoverySession()");
		try {
			if (keyRecoverySession == null) {
				keyRecoverySession = ((IKeyRecoverySessionHome) ServiceLocator.getInstance().getRemoteHome(
						IKeyRecoverySessionHome.JNDI_NAME, IKeyRecoverySessionHome.class)).create();
			}
		} catch (Exception e) {
			baseLog.error("", e);
			throw new RuntimeException(e);
		}
		baseLog.trace("<getKeyRecoverySession()");
        return keyRecoverySession;
     }
    
    /**
     *@return a reference to a UserDataSourceSessionBean
     */
    public IUserDataSourceSessionRemote getUserDataSourceSession(){
    	baseLog.trace(">getUserDataSourceSession()");
		try {
			if (userDataSourceSession == null) {
				userDataSourceSession = ((IUserDataSourceSessionHome) ServiceLocator.getInstance().getRemoteHome(
						IUserDataSourceSessionHome.JNDI_NAME, IUserDataSourceSessionHome.class)).create();
			}
		} catch (Exception e) {
			baseLog.error("", e);
			throw new RuntimeException(e);
		}
		baseLog.trace("<getUserDataSourceSession()");
        return userDataSourceSession;
    }

    /**
     * @return a reference to a (Rsa)SignSessionBean
     */
    public ISignSessionRemote getSignSession(){
    	baseLog.trace(">getSignSession()");
		try {
			if (signSession == null) {
				signSession = ((ISignSessionHome) ServiceLocator.getInstance().getRemoteHome(
						ISignSessionHome.JNDI_NAME, ISignSessionHome.class)).create();
			}
		} catch (Exception e) {
			baseLog.error("", e);
			throw new RuntimeException(e);
		}
		baseLog.trace("<getSignSession()");
        return signSession;
    }

    /**
     * @return a reference to a ConfigurationSessionBean
     */
    public IConfigurationSessionRemote getConfigurationSession(){
    	baseLog.trace(">getConfigurationSession()");
		try {
			if (configurationSession == null) {
				configurationSession = ((IConfigurationSessionHome) ServiceLocator.getInstance().getRemoteHome(
						IConfigurationSessionHome.JNDI_NAME, IConfigurationSessionHome.class)).create();
			}
		} catch (Exception e) {
			baseLog.error("", e);
			throw new RuntimeException(e);
		}
		baseLog.trace("<getConfigurationSession()");
        return configurationSession;
    }

    /**
     * @return a reference to a AuthenticationSessionBean
     */
    public IAuthenticationSessionRemote getAuthenticationSession(){
    	baseLog.trace(">getAuthenticationSession()");
		try {
			if (authenticationSession == null) {
				authenticationSession = ((IAuthenticationSessionHome) ServiceLocator.getInstance().getRemoteHome(
						IAuthenticationSessionHome.JNDI_NAME, IAuthenticationSessionHome.class)).create();
			}
		} catch (Exception e) {
			baseLog.error("", e);
			throw new RuntimeException(e);
		}
		baseLog.trace("<getConfigurationSession()");
        return authenticationSession;
    }

    /**
     * Method checking if the application server is running.
     * 
     * @return true if app server is running.
     */
    protected boolean appServerRunning() {
        // Check that the application server is running by getting a home interface for user admin session
        try {
            ServiceLocator.getInstance().getRemoteHome(ICAAdminSessionHome.JNDI_NAME, ICAAdminSessionHome.class).getClass(); // avoid PMD warning :)
            return true;
        } catch (Exception e) {
        	baseLog.error("Appserver not running: ", e);
            return false;
        }
    }

    /** Private key with length 1024 bits */
    static byte[] keys1024bit = Base64.decode(
    ("MIICeAIBADANBgkqhkiG9w0BAQEFAASCAmIwggJeAgEAAoGBAKA5rNhYbPuVcArT"
    +"mkthfrW2tX1Z7SkCD01sDYrkiwOcodFmS1cSyz8eHM51iwHA7CW0WFvfUjomBT5y"
    +"gRQfIsf5M5DUtYcKM1hmGKSPzvmF4nYv+3UBUesCvBXVRN/wFZ44SZZ3CVvpQUYb"
    +"GWjyC+Dgol5n8oKOC287rnZUPEW5AgMBAAECgYEAhMtoeyLGqLlRVFfOoL1cVGTr"
    +"BMp8ail/30435y7GHKc74p6iwLcd5uEhROhc3oYz8ogHV5W+w9zxKbGjU7b+jmh+"
    +"h/WFao+Gu3sSrZ7ieg95fSuQsBlJp3w+eCAOZwlEu/JQQHDtURui25SPVblZ9/41"
    +"u8VwFjk9YQx+nT6LclECQQDYlC9bOr1SWL8PBlipXB/UszMsTM5xEH920A+JPF4E"
    +"4tw+AHecanjr5bXSluRbWSWUjtl5LV2edqAP9EsH1/A1AkEAvWOctUvTlm6fWHJq"
    +"lZhsWVvOhDG7cn5gFu34J8JJd5QHov0469CpSamY0Q/mPE/y3kDllmyYvnQ+yobB"
    +"ZRg39QJBAINCM/0/eVQ58vlBKGTkL2pyfNYhapB9pjK04GWVD4o4j7CICfXjVYvq"
    +"eSq7RoTSX4NMnCLjyrRqQpHIxdxoE+0CQQCz7MzWWGF+Cz6LUrf7w0E8a8H5SR4i"
    +"GfnEDvSxIR2W4yWWLShEsIoEF4G9LHO5XOMJT3JOxIEgf2OgGQHmv2l5AkBThYUo"
    +"ni82jZuue3YqXXHY2lz3rVmooAv7LfQ63yzHECFsQz7kDwuRVWWRsoCOURtymAHp"
    +"La09g2BE+Q5oUUFx").getBytes());
    /** self signed cert done with above private key */
    static byte[] certbytes = Base64.decode(
    ("MIICNzCCAaCgAwIBAgIIIOqiVwJHz+8wDQYJKoZIhvcNAQEFBQAwKzENMAsGA1UE"
    +"AxMEVGVzdDENMAsGA1UEChMEVGVzdDELMAkGA1UEBhMCU0UwHhcNMDQwNTA4MDkx"
    +"ODMwWhcNMDUwNTA4MDkyODMwWjArMQ0wCwYDVQQDEwRUZXN0MQ0wCwYDVQQKEwRU"
    +"ZXN0MQswCQYDVQQGEwJTRTCBnzANBgkqhkiG9w0BAQEFAAOBjQAwgYkCgYEAgbf2"
    +"Sv34lsY43C8WJjbUd57TNuHJ6p2Es7ojS3D2yxtzQg/A8wL1OfXes344PPNGHkDd"
    +"QPBaaWYQrvLvqpjKwx/vA1835L3I92MsGs+uivq5L5oHfCxEh8Kwb9J2p3xjgeWX"
    +"YdZM5dBj3zzyu+Jer4iU4oCAnnyG+OlVnPsFt6ECAwEAAaNkMGIwDwYDVR0TAQH/"
    +"BAUwAwEB/zAPBgNVHQ8BAf8EBQMDBwYAMB0GA1UdDgQWBBQArVZXuGqbb9yhBLbu"
    +"XfzjSuXfHTAfBgNVHSMEGDAWgBQArVZXuGqbb9yhBLbuXfzjSuXfHTANBgkqhkiG"
    +"9w0BAQUFAAOBgQA1cB6wWzC2rUKBjFAzfkLvDUS3vEMy7ntYMqqQd6+5s1LHCoPw"
    +"eaR42kMWCxAbdSRgv5ATM0JU3Q9jWbLO54FkJDzq+vw2TaX+Y5T+UL1V0o4TPKxp"
    +"nKuay+xl5aoUcVEs3h3uJDjcpgMAtyusMEyv4d+RFYvWJWFzRTKDueyanw==").getBytes());

    /**
     * Method checking if strong crypto is installed (extra package from java.sun.com)
     * 
     * @return true if strong crypto is installed.
     */
    protected boolean strongCryptoInstalled() throws IOException, KeyStoreException, CertificateException, NoSuchProviderException, NoSuchAlgorithmException, InvalidKeySpecException {
        CertTools.installBCProvider();
        Certificate cert = CertTools.getCertfromByteArray(certbytes);
        PKCS8EncodedKeySpec pkKeySpec = new PKCS8EncodedKeySpec(keys1024bit);
        KeyFactory keyFactory = KeyFactory.getInstance("RSA");
        PrivateKey pk = keyFactory.generatePrivate(pkKeySpec);
        KeyStore ks = KeyTools.createP12("Foo", pk, cert, (X509Certificate)null);
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        // If password below is more than 7 chars, strong crypto is needed
        ks.store(baos, "foo1234567890".toCharArray());
        // If we didn't throw an exception, we were succesful
        return true;
    }
    
}
