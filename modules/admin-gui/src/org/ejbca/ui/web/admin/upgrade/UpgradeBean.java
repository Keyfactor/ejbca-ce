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
package org.ejbca.ui.web.admin.upgrade;

import java.io.Serializable;
import java.util.ArrayList;
import java.util.List;
import java.util.TimeZone;

import javax.annotation.PostConstruct;
import javax.ejb.EJB;
import javax.faces.bean.ManagedBean;
import javax.faces.bean.ViewScoped;
import javax.faces.event.AjaxBehaviorEvent;

import org.apache.log4j.Level;
import org.apache.log4j.spi.LoggingEvent;
import org.apache.log4j.spi.ThrowableInformation;
import org.cesecore.authorization.AuthorizationSessionLocal;
import org.cesecore.util.ValidityDate;
import org.ejbca.core.ejb.upgrade.UpgradeSessionLocal;
import org.ejbca.core.ejb.upgrade.UpgradeStatusSingletonLocal;
import org.ejbca.ui.web.admin.BaseManagedBean;

/**
 * JSF Managed Bean for the post upgrade page.
 * 
 * @version $Id$
 */
@ViewScoped // Local variables will live as long as actions on the backed page return "" or void.
@ManagedBean
public class UpgradeBean extends BaseManagedBean implements Serializable {

	/** Wrapper of Log4J LoggingEvents for use in the GUI */
    public static class LogEvent {
        final LoggingEvent loggingEvent;
        public LogEvent(final LoggingEvent loggingEvent) {
            this.loggingEvent = loggingEvent;
        }

        /** @return true for FATAL and ERROR level messages */
        public boolean isLevelError() { return loggingEvent.getLevel().isGreaterOrEqual(Level.ERROR); }
        public boolean isLevelWarning() { return loggingEvent.getLevel().equals(Level.WARN); }
        public boolean isLevelInfo() { return !loggingEvent.getLevel().isGreaterOrEqual(Level.WARN); }

        public String getLevel() { return loggingEvent.getLevel().toString(); }

        public String getTime() { return ValidityDate.formatAsISO8601ServerTZ(loggingEvent.getTimeStamp(), TimeZone.getDefault()); }

        public String getMessage() {
            final StringBuilder sb = new StringBuilder(loggingEvent.getRenderedMessage());
            final ThrowableInformation throwableInformation = loggingEvent.getThrowableInformation();
            if (throwableInformation!=null) {
                Throwable throwable = throwableInformation.getThrowable();
                while (throwable!=null) {
                    sb.append(" <- " + throwable.getMessage());
                    throwable = throwable.getCause();
                }
            }
            return sb.toString();
        }
    }
    
    private static final long serialVersionUID = 1L;
    //private static final Logger log = Logger.getLogger(UpgradeBean.class);
    
    @EJB
    private AuthorizationSessionLocal authorizationSession;
    @EJB
    private UpgradeSessionLocal upgradeSession;
    @EJB
    private UpgradeStatusSingletonLocal upgradeStatusSingleton;

    @PostConstruct
    private void postConstruct() {
    }

    /** @see UpgradeSessionLocal#isPostUpgradeNeeded() */
    public boolean isPostUpgradeRequired() {
        return upgradeSession.isPostUpgradeNeeded();
    }

    /** @return true if the current administrator is authorized to start the upgrade */
    public boolean isAuthorizedToUpgrade() {
        return authorizationSession.isAuthorizedNoLogging(getAdmin(), "/system_functionality/edit_systemconfiguration");
    }

    /** @return true if an upgrade is currently in progress on this node */
    public boolean isPostUpgradeInProgress() {
        return upgradeStatusSingleton.isPostUpgradeInProgress();
    }

    /** @return true if an upgrade is currently in progress on this node */
    public boolean isPostUpgradeFailed() {
        return isActionStartUpgradeAllowed() && !getLogged().isEmpty();
    }

    /** @return true if an upgrade is currently in progress on any node */
    public boolean isPostUpgradeInProgressInCluster() {
        // The first check requires no DB read (which might return cached/stale data), so we check that first
        return upgradeStatusSingleton.isPostUpgradeInProgress() || upgradeSession.getPostUpgradeStarted()!=0L;
    }
    
    /** @return the date when a node began the cluster upgrade procedure */
    public String getPostUpgradeStartedInCluster() {
        return ValidityDate.formatAsISO8601ServerTZ(upgradeSession.getPostUpgradeStarted(), TimeZone.getDefault());
    }

    /** @return true if the administrator is allowed to start the post upgrade procedure */
    public boolean isActionStartUpgradeAllowed() {
        return isPostUpgradeRequired() && !isPostUpgradeInProgress() && !isPostUpgradeInProgressInCluster();
    }

    /** @return true if the administrator is allowed to force a restart of the post upgrade procedure (10 minutes has passed and it is not running on this node) */
    public boolean isActionForceRestartUpgradeAllowed() {
        final long postUpgradeStarted = upgradeSession.getPostUpgradeStarted();
        return isPostUpgradeRequired() && !isPostUpgradeInProgress() && postUpgradeStarted!=0L && postUpgradeStarted+60000L<=System.currentTimeMillis();
    }

    /** @return true is there is specific post-upgrade instructions that should be rendered */
    public boolean isRenderPostUpgradeInfoNotes() {
        return isRenderPostUpgradeInfoTo680();
    }

    /** @return true is this post-upgrade will include an upgrade to EJBCA 6.8.0 */
    public boolean isRenderPostUpgradeInfoTo680() {
        return upgradeSession.isLesserThan(getLastPostUpgradedToVersion(), "6.8.0");
    }

    /** @return info logged by the upgrade code */
    public List<LogEvent> getLogged() {
        final List<LogEvent> ret = new ArrayList<>();
        for (final LoggingEvent loggingEvent: new ArrayList<>(upgradeStatusSingleton.getLogged())) {
            if (loggingEvent.getLevel().isGreaterOrEqual(Level.INFO)) {
                ret.add(new LogEvent(loggingEvent));
            }
        }
        return ret;
    }

    /** @return the newest version of EJBCA connected to the common database */
    public String getLastUpgradedToVersion() {
        return upgradeSession.getLastUpgradedToVersion();
    }

    /** @return the currently effective version of data stored in the database */
    public String getLastPostUpgradedToVersion() {
        return upgradeSession.getLastPostUpgradedToVersion();
    }

    /** Invoked by the user to start the upgrade as a background process */
    public void actionStartUpgrade() {
        upgradeSession.startPostUpgrade();
    }

    /** Invoked by the user to to clear the cluster wide upgrade lock */
    public void actionClearUpgradeLock() {
        upgradeSession.setPostUpgradeStarted(0L);
    }

    /** Noop. Invoked by the user to refresh the page */
    public void actionNoAction() {}

    /** Noop. Invoked by the user to refresh the page */
    public void actionNoActionAjaxListener(final AjaxBehaviorEvent event) {}
}
