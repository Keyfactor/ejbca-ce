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

import javax.ejb.EJBException;
import javax.ejb.Stateless;
import javax.ejb.TransactionAttribute;
import javax.ejb.TransactionAttributeType;
import javax.persistence.EntityManager;
import javax.persistence.PersistenceContext;

import org.apache.log4j.Logger;
import org.ejbca.config.EjbcaConfiguration;
import org.ejbca.core.ejb.JndiHelper;
import org.ejbca.core.ejb.log.LogConfigurationData;
import org.ejbca.core.ejb.log.LogConfigurationSessionLocal;
import org.ejbca.core.ejb.log.LogConfigurationSessionRemote;
import org.ejbca.core.model.InternalResources;
import org.ejbca.core.model.log.LogConfiguration;
import org.ejbca.util.ObjectCache;

/**
 * @see org.ejbca.core.ejb.log.LogConfigurationSession
 * @version $Id$
 */
@Stateless(mappedName = JndiHelper.APP_JNDI_PREFIX + "LogConfigurationSessionRemote")
@TransactionAttribute(TransactionAttributeType.REQUIRED)
public class LogConfigurationSessionBean implements LogConfigurationSessionLocal, LogConfigurationSessionRemote {

	private static final Logger LOG = Logger.getLogger(LogConfigurationSessionBean.class);
    private static final InternalResources INTRES = InternalResources.getInstance();

    @PersistenceContext(unitName="ejbca")
    private EntityManager entityManager;

	/**
     * Cache for log configuration data with default cache time of 5 seconds.
     * 5 seconds is enough to not limit performance in high performance environments, but low enough so that 
     * changes to configuration is visible almost immediately.
     */
    private static final ObjectCache<Integer,LogConfiguration> logConfCache = new ObjectCache<Integer,LogConfiguration>(EjbcaConfiguration.getCacheLogConfigurationTime());

    @TransactionAttribute(TransactionAttributeType.NOT_SUPPORTED)
    @Override
    public LogConfiguration loadLogConfiguration(final int caid) {
        // Try loading log configuration from cache
        LogConfiguration ret = logConfCache.get(Integer.valueOf(caid)); 
    	if (ret == null) {
            // Try loading log configuration from database
    		final LogConfigurationData logconfigdata = LogConfigurationData.findByPK(entityManager, Integer.valueOf(caid));
    		if (logconfigdata != null) {
    			ret = logconfigdata.loadLogConfiguration();
    			logConfCache.put(Integer.valueOf(caid), ret);
    		}
    	}
		if (ret == null) {
			// Use the default object if nothing is configured
			ret = new LogConfiguration();
			logConfCache.put(Integer.valueOf(caid), ret);
		}
        return ret;
    }

    /*
     * We want to read and change as little data as possible here to keep this as quick as possible.
     * If we read the whole LogConfigurationData BLOB the risk that the read LogEntryRowNumber
     * is stale on some databases.
     * 
     * By doing this in a new transaction, we avoid Exceptions when the calling transaction commits.
     */
    @TransactionAttribute(TransactionAttributeType.REQUIRES_NEW)
    @Override
    public int getAndIncrementRowCount() {
    	// Read current value from LogConfigurationData with id=0
    	final int currentLogEntryRowNumber = LogConfigurationData.findCurrentLogEntryRowNumber(entityManager);
    	if (currentLogEntryRowNumber == -1) {
        	// No such LogConfigurationData exists, so we create a new one with an updated logEntryRowNumber...
    		final LogConfigurationData logConfigurationDataNew = new LogConfigurationData(0, new LogConfiguration());
    		logConfigurationDataNew.setLogEntryRowNumber(1);
    		entityManager.persist(logConfigurationDataNew);
    		// ...and return 0, since we know that this is the first anyone has asked for.
    		return 0;
    	} else {
        	// Try an atomic UPDATE of the logEntryRowNumber based on what we just read
    		return LogConfigurationData.incrementLogEntryRowNumber(entityManager, currentLogEntryRowNumber);
    	}
    }

    @TransactionAttribute(TransactionAttributeType.SUPPORTS)
    @Override
    public void flushConfigurationCache() {
    	logConfCache.emptyCache();
    	if (LOG.isDebugEnabled()) {
    		LOG.debug("Flushed log configuration cache.");
    	}
    }

    /*
     * By doing this in a new transaction, we avoid nested transactions with several operations on
     * the same LogConfigurationData row.
     */
    @TransactionAttribute(TransactionAttributeType.REQUIRES_NEW)
	@Override
	public void saveLogConfiguration(int caid, LogConfiguration logConfiguration, boolean updateCache) {
		try {
        	final LogConfigurationData lcd = LogConfigurationData.findByPK(entityManager, Integer.valueOf(caid));
        	if (lcd == null) {
        		LOG.info(INTRES.getLocalizedMessage("log.createconf", Integer.valueOf(caid)));
        		entityManager.persist(new LogConfigurationData(caid, logConfiguration));
        	} else { 
        		lcd.saveLogConfiguration(logConfiguration);
        	}
        	if (updateCache) {
    			logConfCache.put(Integer.valueOf(caid), logConfiguration);
        	}
		} catch (Exception e) {
			LOG.error(INTRES.getLocalizedMessage("log.errorcreateconf", Integer.valueOf(caid)), e);
			throw new EJBException(e);
		}
	}
}
