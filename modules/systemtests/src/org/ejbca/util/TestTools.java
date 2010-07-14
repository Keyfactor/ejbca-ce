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

import java.util.Date;
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

/**
 * Common glue code that can be called from all JUnit tests to make it easier to
 * call remote beans etc.
 * 
 * @version $Id$
 */
public class TestTools {

    private static final Logger log = Logger.getLogger(TestTools.class);
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
                approvalSession = ((IApprovalSessionHome) ServiceLocator.getInstance()
                        .getRemoteHome(IApprovalSessionHome.JNDI_NAME, IApprovalSessionHome.class)).create();
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
                authenticationSession = ((IAuthenticationSessionHome) ServiceLocator.getInstance().getRemoteHome(IAuthenticationSessionHome.JNDI_NAME,
                        IAuthenticationSessionHome.class)).create();
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
                authorizationSession = ((IAuthorizationSessionHome) ServiceLocator.getInstance().getRemoteHome(IAuthorizationSessionHome.JNDI_NAME,
                        IAuthorizationSessionHome.class)).create();
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
                caAdminSession = ((ICAAdminSessionHome) ServiceLocator.getInstance().getRemoteHome(ICAAdminSessionHome.JNDI_NAME, ICAAdminSessionHome.class))
                        .create();
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
                configurationSession = ((IConfigurationSessionHome) ServiceLocator.getInstance().getRemoteHome(IConfigurationSessionHome.JNDI_NAME,
                        IConfigurationSessionHome.class)).create();
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
                certificateStoreSession = ((ICertificateStoreSessionHome) ServiceLocator.getInstance().getRemoteHome(ICertificateStoreSessionHome.JNDI_NAME,
                        ICertificateStoreSessionHome.class)).create();
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
                certificateRequestSession = ((ICertificateRequestSessionHome) ServiceLocator.getInstance().getRemoteHome(
                        ICertificateRequestSessionHome.JNDI_NAME, ICertificateRequestSessionHome.class)).create();
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
                createCRLSession = ((ICreateCRLSessionHome) ServiceLocator.getInstance().getRemoteHome(ICreateCRLSessionHome.JNDI_NAME,
                        ICreateCRLSessionHome.class)).create();
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
                hardTokenSession = ((IHardTokenSessionHome) ServiceLocator.getInstance().getRemoteHome(IHardTokenSessionHome.JNDI_NAME,
                        IHardTokenSessionHome.class)).create();
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
                keyRecoverySession = ((IKeyRecoverySessionHome) ServiceLocator.getInstance().getRemoteHome(IKeyRecoverySessionHome.JNDI_NAME,
                        IKeyRecoverySessionHome.class)).create();
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
                protectedLogSession = ((IProtectedLogSessionHome) ServiceLocator.getInstance().getRemoteHome(IProtectedLogSessionHome.JNDI_NAME,
                        IProtectedLogSessionHome.class)).create();
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
                raAdminSession = ((IRaAdminSessionHome) ServiceLocator.getInstance().getRemoteHome(IRaAdminSessionHome.JNDI_NAME, IRaAdminSessionHome.class))
                        .create();
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
                serviceSession = ((IServiceSessionHome) ServiceLocator.getInstance().getRemoteHome(IServiceSessionHome.JNDI_NAME, IServiceSessionHome.class))
                        .create();
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
                userAdminSession = ((IUserAdminSessionHome) ServiceLocator.getInstance().getRemoteHome(IUserAdminSessionHome.JNDI_NAME,
                        IUserAdminSessionHome.class)).create();
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
                publisherQueueSession = ((IPublisherQueueSessionHome) ServiceLocator.getInstance().getRemoteHome(IPublisherQueueSessionHome.JNDI_NAME,
                        IPublisherQueueSessionHome.class)).create();
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
                publisherSession = ((IPublisherSessionHome) ServiceLocator.getInstance().getRemoteHome(IPublisherSessionHome.JNDI_NAME,
                        IPublisherSessionHome.class)).create();
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
                tableProtectSession = ((TableProtectSessionHome) ServiceLocator.getInstance().getRemoteHome(TableProtectSessionHome.JNDI_NAME,
                        TableProtectSessionHome.class)).create();
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
                userDataSourceSession = ((IUserDataSourceSessionHome) ServiceLocator.getInstance().getRemoteHome(IUserDataSourceSessionHome.JNDI_NAME,
                        IUserDataSourceSessionHome.class)).create();
            }
        } catch (Exception e) {
            log.error("", e);
            return null;
        }
        return userDataSourceSession;
    }
    


}
