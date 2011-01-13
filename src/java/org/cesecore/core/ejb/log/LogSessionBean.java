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

package org.cesecore.core.ejb.log;

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
import javax.persistence.EntityManager;
import javax.persistence.PersistenceContext;

import org.apache.log4j.Logger;
import org.ejbca.config.EjbcaConfiguration;
import org.ejbca.core.ejb.JndiHelper;
import org.ejbca.core.ejb.log.LogConfigurationData;
import org.ejbca.core.model.InternalResources;
import org.ejbca.core.model.log.Admin;
import org.ejbca.core.model.log.ILogDevice;
import org.ejbca.core.model.log.ILogExporter;
import org.ejbca.core.model.log.LogConfiguration;
import org.ejbca.core.model.log.LogConstants;
import org.ejbca.core.model.log.LogEntry;
import org.ejbca.core.model.log.OldLogDevice;
import org.ejbca.util.CertTools;
import org.ejbca.util.ObjectCache;
import org.ejbca.util.query.IllegalQueryException;
import org.ejbca.util.query.Query;

/**
 * Stores data used by web server clients.
 * Uses JNDI name for datasource as defined in env 'Datasource' in ejb-jar.xml.
 *
 *
 * @version $Id$
 */
@Stateless(mappedName = JndiHelper.APP_JNDI_PREFIX + "LogSessionRemote")
@TransactionAttribute(TransactionAttributeType.SUPPORTS)
public class LogSessionBean implements LogSessionLocal, LogSessionRemote {

    private static final Logger LOG = Logger.getLogger(LogSessionBean.class);
    
	/** Internal localization of logs and errors */
    private static final InternalResources INTRES = InternalResources.getInstance();
    
    /** Cache for log configuration data with default cache time of 5 seconds.
     * 5 seconds is enough to not limit performance in high performance environments, but low enough so that 
     * changes to configuration is visible almost immediately.
     */
    private static final ObjectCache logConfCache = new ObjectCache(EjbcaConfiguration.getCacheLogConfigurationTime());

    @PersistenceContext(unitName="ejbca")
    private EntityManager entityManager;

    @Resource
    private SessionContext sessionContext;

    @EJB
    private OldLogSessionLocal oldLogSession;	// Injected into OldLogDevice (if used).
    private LogSessionLocal logSession;	// Reference to an instance of this SSB to be able to get the right transaction attributes.

    /** Collection of available log devices, i.e Log4j etc */
    private List<ILogDevice> logdevices;

    @PostConstruct
    public void ejbCreate() {
        try {
        	logSession = sessionContext.getBusinessObject(LogSessionLocal.class);
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
    
    public Collection<String> getAvailableLogDevices() {
    	final ArrayList<String> ret = new ArrayList<String>();
    	final Iterator<ILogDevice> i = logdevices.iterator();
    	while (i.hasNext()) {
    		ret.add( i.next().getDeviceName() );
    	}
    	Collections.reverse(ret);
    	return ret;
    }

    /**
     * Session beans main function. Takes care of the logging functionality.
     *
     * @param admin the administrator performing the event.
     * @param time the time the event occurred.
     * @param username the name of the user involved or null if no user is involved.
     * @param certificate the certificate involved in the event or null if no certificate is involved.
     * @param event id of the event, should be one of the org.ejbca.core.model.log.LogConstants.EVENT_ constants.
     * @param comment comment of the event.
     */
    public void log(final Admin admin, final int caid, final int module, final Date time, final String username, final Certificate certificate, final int event, final String comment) {
        doLog(admin, caid, module, time, username, certificate, event, comment, null);
    }

    /**
     * Same as above but with the difference of CAid which is taken from the issuerdn of given certificate.
     */
    public void log(final Admin admin, final Certificate caid, final int module, final Date time, final String username, final Certificate certificate, final int event, final String comment) {
        doLog(admin, CertTools.getIssuerDN(caid).hashCode(), module, time, username, certificate, event, comment, null);
    }

    /**
     * Overloaded function that also logs an exception
     * See function above for more documentation.
     *
     * @param exception the exception that has occured
     */
    public void log(final Admin admin, final int caid, final int module, final Date time, final String username, final Certificate certificate, final int event, final String comment, final Exception exception) {
        doLog(admin, caid, module, time, username, certificate, event, comment, exception);
    }

    /**
     * Same as above but with the difference of CAid which is taken from the issuerdn of given certificate.
     */
    public void log(final Admin admin, final Certificate caid, final int module, final Date time, final String username, final Certificate certificate, final int event, final String comment, final Exception exception) {
        doLog(admin, CertTools.getIssuerDN(caid).hashCode(), module, time, username, certificate, event, comment, exception);
    }

    /**
     * Internal implementation for logging. Does not allow Exceptions to propagate outside the logging functionality.
     */
    private void doLog(final Admin admin, final int caid, final int module, final Date time, final String username, final Certificate certificate, final int event, final String comment, final Exception ex) {
    	final Iterator<ILogDevice> i = logdevices.iterator();
    	while (i.hasNext()) {
    		final ILogDevice dev = i.next();
    		try {
    	    	final LogConfiguration config = loadLogConfiguration(caid);
    	    	if (!dev.getAllowConfigurableEvents() || config.logEvent(event)) {
    	    		dev.log(admin, caid, module, time, username, certificate, event, comment, ex);
    	    	}
    		} catch (Throwable e) { // NOPMD, we really want to catch every possible error from the log device
            	LOG.error(INTRES.getLocalizedMessage("log.error.logdropped",admin.getAdminType()+" "+admin.getAdminData()+" "
            			+caid+" "+" "+module+" "+" "+time+" "+username+" "+(certificate==null?"null":CertTools.getSerialNumberAsString(certificate)+" "
               			+CertTools.getIssuerDN(certificate))+" "+event+" "+comment+" "+ex));
            	final String msg = INTRES.getLocalizedMessage("log.errormissingentry");
    			LOG.error(msg, e);
    		}
        }
    }

    /**
     * Method to export log records according to a customized query on the log db data. The parameter query should be a legal Query object.
     *
     * @param query a number of statments compiled by query class to a SQL 'WHERE'-clause statment.
     * @param viewlogprivileges is a sql query string returned by a LogAuthorization object.
     * @param logexporter is the obbject that converts the result set into the desired log format 
     * @return an exported byte array. Maximum number of exported entries is defined i LogConstants.MAXIMUM_QUERY_ROWCOUNT, returns null if there is nothing to export
     * @throws IllegalQueryException when query parameters internal rules isn't fullfilled.
     * @throws Exception differs depending on the ILogExporter implementation
     * @see org.ejbca.util.query.Query
     *
     */
    public byte[] export(final String deviceName, final Admin admin, final Query query, final String viewlogprivileges, final String capriviledges, final ILogExporter logexporter, final int maxResults) throws IllegalQueryException, Exception {
    	byte[] result = null;
    	final Iterator<ILogDevice> i = logdevices.iterator();
        while (i.hasNext()) {
        	final ILogDevice dev = i.next();
            if (dev.getDeviceName().equalsIgnoreCase(deviceName)) {
            	result = dev.export(admin, query, viewlogprivileges, capriviledges, logexporter, maxResults);
            	break;
            }
        }
		return result;
    }
    
    /**
     * Method to execute a customized query on the log db data. The parameter query should be a legal Query object.
     *
     * @param query a number of statments compiled by query class to a SQL 'WHERE'-clause statment.
     * @param viewlogprivileges is a sql query string returned by a LogAuthorization object.
     * @return a collection of LogEntry. Maximum size of Collection is defined i LogConstants.MAXIMUM_QUERY_ROWCOUNT
     * @throws IllegalQueryException when query parameters internal rules isn't fullfilled.
     * @see org.ejbca.util.query.Query
     */
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

    /**
     * Loads the log configuration from the database.
     *
     * @return the logconfiguration
     */
    public LogConfiguration loadLogConfiguration(final int caid) {
        // Check if log configuration exists, else create one.
        LogConfiguration ret = null; 
        final Object o = logConfCache.get(Integer.valueOf(caid));
    	if (o == null) {
    		final LogConfigurationData logconfigdata = LogConfigurationData.findByPK(entityManager, Integer.valueOf(caid));
    		if (logconfigdata == null) {
    			if (LOG.isDebugEnabled()) {
    				LOG.debug("Can't find log configuration during load (caid="+caid+"), trying to create new.");
    			}
    			try {
    				ret = new LogConfiguration();
    				logSession.saveNewLogConfiguration(caid, ret);	// Need invocation through interface to start transaction
    			} catch (Exception f) {
    				final String msg = INTRES.getLocalizedMessage("log.errorcreateconf", Integer.valueOf(caid));            	
    				LOG.error(msg, f);
    				throw new EJBException(f);
    			}
    		} else {
    			ret = logconfigdata.loadLogConfiguration();
    		}
    		if (ret != null) {
    			logConfCache.put(Integer.valueOf(caid), ret);
    		}
    	} else {
    		ret = (LogConfiguration)o;
    	}
        return ret;
    }

    /**
     * Saves the log configuration to the database without logging.
     * Should only be used from loadLogConfiguration(..)
     * @param logConfiguration the logconfiguration to save.
     */
    @TransactionAttribute(TransactionAttributeType.REQUIRES_NEW)
    public void saveNewLogConfiguration(final int caid, final LogConfiguration logConfiguration) {
		entityManager.persist(new LogConfigurationData(caid, logConfiguration));
        // Update cache
		logConfCache.put(Integer.valueOf(caid), logConfiguration);
    }
    
    /**
     * Saves the log configuration to the database.
     *
     * @param logconfiguration the logconfiguration to save.
     */
    @TransactionAttribute(TransactionAttributeType.REQUIRED)
    public void saveLogConfiguration(final Admin admin, final int caid, final LogConfiguration logconfiguration) {
    	internalSaveLogConfigurationNoFlushCache(admin, caid, logconfiguration);
        // Update cache
		logConfCache.put(Integer.valueOf(caid), logconfiguration);    	
    }
    
    /** Do not use, use saveLogConfiguration instead.
     * Used internally for testing only. Updates configuration without flushing caches.
     */
    @TransactionAttribute(TransactionAttributeType.REQUIRED)
    public void internalSaveLogConfigurationNoFlushCache(final Admin admin, final int caid, final LogConfiguration logconfiguration) {
        try {
        	log(admin, caid, LogConstants.MODULE_LOG, new Date(), null, null, LogConstants.EVENT_INFO_EDITLOGCONFIGURATION, "");
        	final LogConfigurationData lcd = LogConfigurationData.findByPK(entityManager, Integer.valueOf(caid));
        	if (lcd == null) {
        		final String msg = INTRES.getLocalizedMessage("log.createconf", Integer.valueOf(caid));            	
        		LOG.info(msg);
        		entityManager.persist(new LogConfigurationData(caid, logconfiguration));
        	} else { 
        		lcd.saveLogConfiguration(logconfiguration);
        	}
        } catch (Exception e) {
            log(admin, caid, LogConstants.MODULE_LOG, new Date(), null, null, LogConstants.EVENT_ERROR_EDITLOGCONFIGURATION, "");
            throw new EJBException(e);
        }
    }

    /**
     * Clear and reload log profile caches.
     */
    @TransactionAttribute(TransactionAttributeType.SUPPORTS)
    public void flushConfigurationCache() {
    	logConfCache.emptyCache();
    	if (LOG.isDebugEnabled()) {
    		LOG.debug("Flushed log configuration cache.");
    	}
    }

	/**
     * Methods for testing that a log-row is never rolled back if the rest of the transaction is.
     */
    @TransactionAttribute(TransactionAttributeType.REQUIRES_NEW)
	public void testRollback(final long rollbackTestTime) {
    	final Admin internalAdmin = new Admin(Admin.TYPE_INTERNALUSER);
		log(internalAdmin, internalAdmin.getCaId(), LogConstants.MODULE_CUSTOM, new Date(rollbackTestTime), null, null,
				LogConstants.EVENT_INFO_UNKNOWN, "Test of rollback resistance of log-system.", null);
		throw new EJBException("Test of rollback resistance of log-system.");
	}
}
