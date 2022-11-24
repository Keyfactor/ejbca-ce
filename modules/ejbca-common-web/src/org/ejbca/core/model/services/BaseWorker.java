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
package org.ejbca.core.model.services;

import java.util.ArrayList;
import java.util.Collection;
import java.util.List;
import java.util.Properties;

import org.apache.commons.lang.StringUtils;
import org.apache.log4j.Logger;
import org.cesecore.authentication.tokens.AuthenticationToken;
import org.cesecore.certificates.ca.CAConstants;
import org.cesecore.certificates.ca.CaSessionLocal;
import org.ejbca.core.model.InternalEjbcaResources;
import org.ejbca.core.model.SecConst;
import org.ejbca.core.model.services.intervals.DummyInterval;

/**
 * Abstract base class that initializes the worker and its interval and action.
 *  
 */
public abstract class BaseWorker implements IWorker {

    public static final String ERROR_EXPIRE_WORKER_MISCONFIG = "services.errorexpireworker.errorconfig";
    private static final String ERROR_ACTION_CLASSPATH_MISCONFIG = "services.erroractionclasspath";
    
	private static final Logger log = Logger.getLogger(BaseWorker.class);
    /** Internal localization of logs and errors */
    private static final InternalEjbcaResources intres = InternalEjbcaResources.getInstance();

    protected Properties properties = null;
    protected String serviceName = null;
    protected ServiceConfiguration serviceConfiguration = null;
    /** The time this service should have been running. Usually this is 'now'. But is the appserver was down it can have been delayed execution */
    protected long runTimeStamp;
    /** The next time the service is scheduled to run */
    protected long nextRunTimeStamp;
    private IAction action = null;
    private IInterval interval = null;
    
    protected AuthenticationToken admin = null;

    // Cached data
	private transient Collection<Integer> cAIdsToCheck = null;
	private transient long timeBeforeExpire = -1;

	/**
	 * @see org.ejbca.core.model.services.IWorker#init(org.ejbca.core.model.services.ServiceConfiguration, java.lang.String)
	 */
	@Override
	public void init(AuthenticationToken admin, ServiceConfiguration serviceConfiguration,
			String serviceName, long runTimeStamp, long nextRunTimeStamp) {
		this.admin = admin;
		this.serviceName = serviceName;
		this.runTimeStamp = runTimeStamp;
		this.nextRunTimeStamp = nextRunTimeStamp;
		this.serviceConfiguration = serviceConfiguration;
		this.properties = serviceConfiguration.getWorkerProperties();
		
		String actionClassPath = serviceConfiguration.getActionClassPath();
		if(actionClassPath != null){
			try {
				action = (IAction) Thread.currentThread().getContextClassLoader().loadClass(actionClassPath).newInstance();
				action.init(serviceConfiguration.getActionProperties(), serviceName);
			} catch (Exception e) {
				String msg = intres.getLocalizedMessage(ERROR_ACTION_CLASSPATH_MISCONFIG, serviceName);
				log.error(msg,e);
			}       
		}else{
			log.debug("Warning no action class i defined for the service " + serviceName);
		}
		
		String intervalClassPath = serviceConfiguration.getIntervalClassPath();
		if(intervalClassPath != null){
			try {
				interval = (IInterval) Thread.currentThread().getContextClassLoader().loadClass(intervalClassPath).newInstance();
				interval.init(serviceConfiguration.getIntervalProperties(), serviceName);
			} catch (Exception e) {
				String msg = intres.getLocalizedMessage("services.errorintervalclasspath", serviceName);
				log.error(msg,e);
			}       
		}else{
			String msg = intres.getLocalizedMessage("services.errorintervalclasspath", serviceName);
			log.error(msg);
		}
		
		if(interval == null){
			interval = new DummyInterval();
		}

	}

	
	/**
	 * @see org.ejbca.core.model.services.IWorker#getNextInterval()
	 */
	@Override
	public long getNextInterval() {		
		return interval.getTimeToExecution();
	}
	
	protected IAction getAction(){
		if(action == null){
			String msg = intres.getLocalizedMessage(ERROR_ACTION_CLASSPATH_MISCONFIG, serviceName);
			log.error(msg);
		}
		return action;
	}
	
	/**
	 * Returns the admin that should be used for other calls.
	 */
	protected AuthenticationToken getAdmin(){
		return admin;
	}
	
	/**
	 * @return Returns the amount of time, in milliseconds that the property is configured for.
	 * @see IWorker#PROP_TIMEUNIT
	 * @see IWorker#PROP_TIMEBEFOREEXPIRING
	 * @throws ServiceExecutionFailedException
	 */
	protected long getTimeBeforeExpire() throws ServiceExecutionFailedException {
	    // Use default property keys
	    return getTimeBeforeExpire(PROP_TIMEUNIT, PROP_TIMEBEFOREEXPIRING);
	}
	
	/**
	 * @param propertyTimeUnit property key for time unit. E.g. IWorker.PROP_TIMEUNIT
	 * @param propertyTimeValue property key for time value. E.g. IWorker.PROP_TIMEBEFOREEXPIRING
	 * @return Returns the amount of time, in milliseconds that the property is configured for.
	 * @throws ServiceExecutionFailedException if time isn't configured properly.
	 */
    protected long getTimeBeforeExpire(String propertyTimeUnit, String propertyTimeValue) throws ServiceExecutionFailedException {
        if (timeBeforeExpire == -1) {
            String unit = properties.getProperty(propertyTimeUnit);
            if (unit == null) {
                String msg = intres.getLocalizedMessage(ERROR_EXPIRE_WORKER_MISCONFIG, serviceName, "UNIT");
                throw new ServiceExecutionFailedException(msg);
            }
            int unitval = 0;
            for (int i = 0; i < AVAILABLE_UNITS.length; i++) {
                if (AVAILABLE_UNITS[i].equalsIgnoreCase(unit)) {
                    unitval = AVAILABLE_UNITSVALUES[i];
                    break;
                }
            }
            if (unitval == 0) {
                String msg = intres.getLocalizedMessage(ERROR_EXPIRE_WORKER_MISCONFIG, serviceName, "UNIT");
                throw new ServiceExecutionFailedException(msg);
            }


            int intvalue = 0;
            try {
                intvalue = Integer.parseInt(properties.getProperty(propertyTimeValue));
            } catch (NumberFormatException e) {
                String msg = intres.getLocalizedMessage(ERROR_EXPIRE_WORKER_MISCONFIG, serviceName, "VALUE");
                throw new ServiceExecutionFailedException(msg);
            }

            if (intvalue == 0) {
                String msg = intres.getLocalizedMessage("ERROR_EXPIRE_WORKER_MISCONFIG", serviceName, "VALUE");
                throw new ServiceExecutionFailedException(msg);
            }
            timeBeforeExpire = intvalue * unitval;
        }

        return timeBeforeExpire * 1000;
    }

	/**
	 * Get a collection of CA IDS from the property BaseWorker.PROP_CAIDSTOCHECK.
	 *
	 * @param includeAllCAsIfNull set to true if the 'catch all' SecConst.ALLCAS should be included in the list if the property
	 * BaseWorker.PROP_CAIDSTOCHECK does not exist. This is due to that the feature of selecting CAs was enabled in EJBCA 3.9.1,
	 * and we want the service to keep working even after an upgrade from an earlier version.
	 * @return a collection of integer CA IDs.
	 * @throws ServiceExecutionFailedException if a CA ID could not be parsed as an integer, which should not normally happen.
	 */
	protected Collection<Integer> getCAIdsToCheck(boolean includeAllCAsIfNull) throws ServiceExecutionFailedException {
		if(cAIdsToCheck == null){
			cAIdsToCheck = new ArrayList<>();
			String cas = properties.getProperty(PROP_CAIDSTOCHECK);
		    if (log.isDebugEnabled()) {
		    	log.debug("CAIds to check: "+cas);
		    }
			if (!StringUtils.isEmpty(cas)) {
				String[] caids = cas.split(";");
				for(int i=0;i<caids.length;i++ ){
					try {
						Integer.valueOf(caids[i]);
					} catch (NumberFormatException e) {
						String msg = intres.getLocalizedMessage(ERROR_EXPIRE_WORKER_MISCONFIG, serviceName, PROP_CAIDSTOCHECK);
						throw new ServiceExecutionFailedException(msg, e);						
					}
					cAIdsToCheck.add(Integer.valueOf(caids[i]));
				}				
			} else if (includeAllCAsIfNull) {
				cAIdsToCheck.add(SecConst.ALLCAS);
			}
		}
		return cAIdsToCheck;
	}

	/**
	 * Return Ids for all CAs if ALLCAS constant is found in the PROP_CAIDSTOCHECK.
	 *
	 * @param caSession Session for CAs.
	 * @param includeAllCAsIfNull set to true if the 'catch all' CAConstants.ALLCAS should be included in the list if the property
	 * 	      	                  BaseWorker.PROP_CAIDSTOCHECK does not exist.
	 * @return a collection of integer CA IDs.
	 */
	protected Collection<Integer> getAllCAIdsToCheck(CaSessionLocal caSession, boolean includeAllCAsIfNull) throws ServiceExecutionFailedException {
		Collection<Integer> caIdsToCheck = getCAIdsToCheck(includeAllCAsIfNull);

		if (caIdsToCheck != null && caIdsToCheck.contains(CAConstants.ALLCAS)) {
			caIdsToCheck = caSession.getAllCaIds();
		}

		return caIdsToCheck;
	}
	
	protected static String constructNameList(List<String> names) {
	    StringBuilder result = new StringBuilder();
        for (String name : names) {
            result.append(name + ", ");
        }
        return result.substring(0, result.length() - 2);
	}
}
