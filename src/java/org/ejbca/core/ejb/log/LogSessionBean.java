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

package org.ejbca.core.ejb.log;

import java.lang.reflect.Method;
import java.security.cert.Certificate;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;
import java.util.Date;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.Map.Entry;

import javax.annotation.PostConstruct;
import javax.annotation.Resource;
import javax.ejb.EJB;
import javax.ejb.EJBException;
import javax.ejb.SessionContext;
import javax.ejb.Stateless;
import javax.ejb.TransactionAttribute;
import javax.ejb.TransactionAttributeType;

import org.apache.log4j.Logger;
import org.cesecore.certificates.util.CertTools;
import org.ejbca.core.ejb.JndiHelper;
import org.ejbca.core.model.InternalResources;
import org.ejbca.core.model.log.Admin;
import org.ejbca.core.model.log.ILogDevice;
import org.ejbca.core.model.log.LogConfiguration;
import org.ejbca.core.model.log.LogConstants;
import org.ejbca.core.model.log.LogEntry;
import org.ejbca.core.model.log.OldLogDevice;
import org.ejbca.util.query.IllegalQueryException;
import org.ejbca.util.query.Query;

/**
 * Stores data used by web server clients.
 *
 * @version $Id$
 */
@Stateless(mappedName = JndiHelper.APP_JNDI_PREFIX + "LogSessionRemote")
@TransactionAttribute(TransactionAttributeType.SUPPORTS)
public class LogSessionBean implements LogSessionLocal, LogSessionRemote {

    private static final Logger LOG = Logger.getLogger(LogSessionBean.class);
    
	/** Internal localization of logs and errors */
    private static final InternalResources INTRES = InternalResources.getInstance();
    
    @Resource
    private SessionContext sessionContext;

    @EJB
    private OldLogSessionLocal oldLogSession;	// Injected into OldLogDevice (if used).
    @EJB
    private LogConfigurationSessionLocal logConfigurationSession;

    /** Collection of available log devices, i.e Log4j etc */
    private List<ILogDevice> logdevices;

    @PostConstruct
    public void ejbCreate() {
        try {
            // Setup Connection to signing devices.
            logdevices = new ArrayList<ILogDevice>();
            // Load logging properties dynamically as internal resource
            final Map<String,String> logDeviceMap = org.ejbca.config.LogConfiguration.getUsedLogDevices();
            final Set<Entry<String, String>> entries = logDeviceMap.entrySet();
            final Iterator<Map.Entry<String,String>> i = entries.iterator();
            while (i.hasNext()) {
            	final Map.Entry<String, String> entry = i.next();
            	final String deviceName = entry.getKey();
            	final String deviceImpl = entry.getValue();
            	if (LOG.isDebugEnabled()) {
            		LOG.debug("Creating log device: "+deviceName+", "+deviceImpl);
            	}
            	// Create log class
            	final Class implClass = Class.forName(deviceImpl);
                final Object fact = implClass.newInstance();
                final Class[] paramTypes = new Class[] {String.class};
                final Method method = implClass.getMethod("makeInstance", paramTypes);
                final Object[] params = new Object[1];
                params[0] = deviceName;
                logdevices.add((ILogDevice) method.invoke(fact, params));
            }
        	// Workaround to be able to avoid local ENC lookup and use injection instead.
            for (ILogDevice logDevice : logdevices) {
            	if (logDevice instanceof OldLogDevice) {
            		((OldLogDevice)logDevice).setOldLogSessionInterface(oldLogSession);
            	}
            }
        } catch (Exception e) {
            throw new EJBException(e);
        }
    }
    
    @Override
    public Collection<String> getAvailableLogDevices() {
    	final ArrayList<String> ret = new ArrayList<String>();
    	final Iterator<ILogDevice> i = logdevices.iterator();
    	while (i.hasNext()) {
    		ret.add( i.next().getDeviceName() );
    	}
    	Collections.reverse(ret);
    	return ret;
    }

    @Override
    public Collection<String> getAvailableQueryLogDevices() {
    	final ArrayList<String> ret = new ArrayList<String>();
    	final Iterator<ILogDevice> i = logdevices.iterator();
    	while (i.hasNext()) {
    		final ILogDevice logDevice = i.next();
    		if (logDevice.isSupportingQueries()) {
        		ret.add( logDevice.getDeviceName() );
    		}
    	}
    	Collections.reverse(ret);
    	return ret;
    }

    @Override
    public void log(final Admin admin, final int caid, final int module, final Date time, final String username, final Certificate certificate, final int event, final String comment) {
        doLog(admin, caid, module, time, username, certificate, event, comment, null);
    }

    @Override
    public void log(final Admin admin, final Certificate caid, final int module, final Date time, final String username, final Certificate certificate, final int event, final String comment) {
        doLog(admin, CertTools.getIssuerDN(caid).hashCode(), module, time, username, certificate, event, comment, null);
    }

    @Override
    public void log(final Admin admin, final int caid, final int module, final Date time, final String username, final Certificate certificate, final int event, final String comment, final Exception exception) {
        doLog(admin, caid, module, time, username, certificate, event, comment, exception);
    }

    @Override
    public void log(final Admin admin, final Certificate caid, final int module, final Date time, final String username, final Certificate certificate, final int event, final String comment, final Exception exception) {
        doLog(admin, CertTools.getIssuerDN(caid).hashCode(), module, time, username, certificate, event, comment, exception);
    }

    /**
     * Internal implementation for logging. Does not allow Exceptions to propagate outside the logging functionality.
     */
    private void doLog(final Admin admin, final int caid, final int module, final Date time, final String username, final Certificate certificate, final int event, final String comment, final Exception ex) {
    	final LogConfiguration config = logConfigurationSession.loadLogConfiguration(caid);
    	final Iterator<ILogDevice> i = logdevices.iterator();
    	while (i.hasNext()) {
    		final ILogDevice dev = i.next();
    		try {
    	    	if (!dev.getAllowConfigurableEvents() || config.logEvent(event)) {
    	    		dev.log(admin, caid, module, time, username, certificate, event, comment, ex);
    	    	}
    		} catch (Throwable e) { // NOPMD, we really want to catch every possible error from the log device
            	LOG.error(INTRES.getLocalizedMessage("log.error.logdropped",admin.getAdminType()+" "+admin.getAdminData()+" "
            			+caid+" "+" "+module+" "+" "+time+" "+username+" "+(certificate==null?"null":CertTools.getSerialNumberAsString(certificate)+" "
               			+CertTools.getIssuerDN(certificate))+" "+event+" "+comment+" "+ex));
    			LOG.error(INTRES.getLocalizedMessage("log.errormissingentry"), e);
    		}
        }
    }

    @Override
    public Collection<LogEntry> query(final String deviceName, final Query query, final String viewlogprivileges, final String capriviledges, final int maxResults) throws IllegalQueryException {
    	if (LOG.isTraceEnabled()) {
    		LOG.trace(">query()");
    	}
    	Collection<LogEntry> result = null;
    	final Iterator<ILogDevice> i = logdevices.iterator();
        while (i.hasNext()) {
        	final ILogDevice dev = i.next();
            if (dev.getDeviceName().equalsIgnoreCase(deviceName)) {
                result = dev.query(query, viewlogprivileges, capriviledges, maxResults);
                break;
            }
        }
		return result;
    }

    @TransactionAttribute(TransactionAttributeType.REQUIRED)
    @Override
    public void saveLogConfiguration(final Admin admin, final int caid, final LogConfiguration logconfiguration) {
        try {
        	logConfigurationSession.saveLogConfiguration(caid, logconfiguration, true);
        	log(admin, caid, LogConstants.MODULE_LOG, new Date(), null, null, LogConstants.EVENT_INFO_EDITLOGCONFIGURATION, "");
        } catch (Exception e) {
            log(admin, caid, LogConstants.MODULE_LOG, new Date(), null, null, LogConstants.EVENT_ERROR_EDITLOGCONFIGURATION, "");
            throw new EJBException(e);
        }
    }
    
    @TransactionAttribute(TransactionAttributeType.REQUIRES_NEW)
    @Override
	public void testRollback(final long rollbackTestTime) {
    	final Admin internalAdmin = Admin.getInternalAdmin();
		log(internalAdmin, internalAdmin.getCaId(), LogConstants.MODULE_CUSTOM, new Date(rollbackTestTime), null, null,
				LogConstants.EVENT_INFO_UNKNOWN, "Test of rollback resistance of log-system.", null);
		throw new EJBException("Test of rollback resistance of log-system.");
	}
}
