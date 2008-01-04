package org.ejbca.core.model.log;

import java.io.Serializable;
import java.net.InetAddress;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.Date;
import java.util.Iterator;
import java.util.Properties;

import javax.ejb.EJBException;

import org.apache.commons.lang.StringUtils;
import org.apache.log4j.Logger;
import org.ejbca.core.ejb.ServiceLocator;
import org.ejbca.core.ejb.log.IProtectedLogSessionLocal;
import org.ejbca.core.ejb.log.IProtectedLogSessionLocalHome;
import org.ejbca.core.model.InternalResources;
import org.ejbca.core.model.ca.caadmin.CADoesntExistsException;
import org.ejbca.core.model.ca.caadmin.extendedcaservices.ExtendedCAServiceNotActiveException;
import org.ejbca.core.model.ca.caadmin.extendedcaservices.ExtendedCAServiceRequestException;
import org.ejbca.core.model.ca.caadmin.extendedcaservices.IllegalExtendedCAServiceRequestException;
import org.ejbca.util.query.IllegalQueryException;
import org.ejbca.util.query.Query;

/**
 * Implements a log device using a protected log. Implementes the Singleton pattern.
 *
 */
public class ProtectedLogDevice implements ILogDevice, Serializable {

	public final static String CONFIG_TOKENREFTYPE						= "protectionTokenReferenceType";
	public final static String CONFIG_TOKENREFTYPE_CANAME		= "CAName"; 
	public final static String CONFIG_TOKENREFTYPE_URI				= "URI"; 
	public final static String CONFIG_TOKENREFTYPE_NONE			= "none"; 
	public final static String CONFIG_TOKENREFTYPE_DATABASE	= "StoredInDatabase"; 
	public final static String CONFIG_TOKENREFTYPE_CONFIG		= "Base64EncodedConfig"; 

	public final static String CONFIG_TOKENREF								= "protectionTokenReference";
	public final static String CONFIG_KEYSTOREALIAS					= "protectionTokenKeyStoreAlias";
	public final static String CONFIG_KEYSTOREPASSWORD			= "protectionTokenKeyStorePassword";
	public final static String CONFIG_HASHALGO							= "protectionHashAlgorithm";
	public final static String CONFIG_NODEIP									= "nodeIP";
	public final static String CONFIG_PROTECTION_INTENSITY		= "protectionIntensity";
	public final static String CONFIG_ALLOW_EVENTSCONFIG		= "allowConfigurableEvents";
	public final static String CONFIG_LINKIN_INTENSITY					= "linkinIntensity";
	public final static String CONFIG_VERIFYOWN_INTENSITY			= "verifyownIntensity";
	
	public final static String DEFAULT_NODEIP								= "127.0.0.1";
	public final static String DEFAULT_DEVICE_NAME						= "ProtectedLogDevice";
	
	private static final Logger log = Logger.getLogger(ProtectedLogDevice.class);
    private static final InternalResources intres = InternalResources.getInstance();

	private static final SecureRandom seeder = new SecureRandom();

	private static Admin internalAdmin = new Admin(Admin.TYPE_INTERNALUSER);

	private IProtectedLogSessionLocal protectedLogSession = null;
	
	/**
	 * A handle to the unique Singleton instance.
	 */
	private static ILogDevice instance;
	private boolean isDestructorInvoked;
	private boolean systemShutdownNotice;
	private Properties properties;
	private int nodeGUID;
	private long counter;
	private byte[] lastProtectedLogRowHash;
	private long lastTime;
	private long protectionIntensity;
	private String nodeIP = DEFAULT_NODEIP;
	private ProtectedLogToken protectedLogToken;
	private String protectionHashAlgorithm;
	private boolean isFirstLogEvent;
	private ProtectedLogActions protectedLogActions;
	private boolean allowConfigurableEvents;
	private String deviceName;
	private long lastTimeOfSearchForLogEvents;
	private long lastTimeOfSearchForOwnLogEvent;
	private long intensityOfSearchForLogEvents;
	private long intensityOfSearchForOwnLogEvent;
	
	protected ProtectedLogDevice(Properties properties) throws Exception {
		resetDevice(properties);
	}
	
	/**
	 * @see org.ejbca.core.model.log.ILogDevice
	 */
	public void resetDevice(Properties properties) {
		// Init of local variables
		isDestructorInvoked = false;
		systemShutdownNotice = false;
		lastProtectedLogRowHash = null;
		lastTime = 0;
		protectionIntensity = 0;
		protectedLogToken = null;
		isFirstLogEvent = true;
		allowConfigurableEvents = false;
		lastTimeOfSearchForLogEvents = 0;
		lastTimeOfSearchForOwnLogEvent = 0;
		// Init depending on properties
		this.properties = properties;
		deviceName = properties.getProperty(ILogDevice.PROPERTY_DEVICENAME, DEFAULT_DEVICE_NAME);
		nodeGUID = seeder.nextInt();
		counter = 0;
		protectionIntensity = Long.parseLong(properties.getProperty(CONFIG_PROTECTION_INTENSITY, "0")) * 1000; 
		allowConfigurableEvents = properties.getProperty(CONFIG_ALLOW_EVENTSCONFIG, "false").equalsIgnoreCase("true"); 
		protectionHashAlgorithm = properties.getProperty(CONFIG_HASHALGO, "SHA-256");
        try {
        	nodeIP = InetAddress.getLocalHost().getHostAddress();
        }
        catch (java.net.UnknownHostException uhe) {
        }
		nodeIP = properties.getProperty(CONFIG_NODEIP, nodeIP);
		protectedLogActions = new ProtectedLogActions(properties);
		if (protectionIntensity != 0 && properties.getProperty(ProtectedLogExporter.CONF_DELETE_AFTER_EXPORT, "false").equalsIgnoreCase("true")) {
	    	log.warn(intres.getLocalizedMessage("protectedlog.warn.usingunsafeconfig", ProtectedLogExporter.CONF_DELETE_AFTER_EXPORT, CONFIG_PROTECTION_INTENSITY));
		}
		if (properties.getProperty(CONFIG_TOKENREFTYPE, CONFIG_TOKENREFTYPE_NONE).equalsIgnoreCase(CONFIG_TOKENREFTYPE_NONE)) {
			// Disable link-in searches since no real token is used anyway..
			intensityOfSearchForLogEvents = -1000;
			intensityOfSearchForOwnLogEvent = -1000;
		} else  {
			intensityOfSearchForLogEvents = Long.parseLong(properties.getProperty(CONFIG_LINKIN_INTENSITY, "1")) * 1000; 
			intensityOfSearchForOwnLogEvent = Long.parseLong(properties.getProperty(CONFIG_VERIFYOWN_INTENSITY, "1")) * 1000; 
		}
	}

	/**
	 * Creates (if needed) the log device and returns the object.
	 *
	 * @param prop Arguments needed for the eventual creation of the object
	 * @return An instance of the log device.
	 */
	public static synchronized ILogDevice instance(Properties prop) throws Exception {
		if (instance == null) {
			instance = new ProtectedLogDevice(prop);
		}
		return instance;
	}

	/**
	 * @return the existing device or null if none exist.
	 */
	public static synchronized ILogDevice instance() {
		return instance;
	}
	
	/**
	 * Should only be called by the StartServicesServlet.
	 */
	public void setSystemShutdownNotice() {
		log(internalAdmin, internalAdmin.getCaId(), LogConstants.MODULE_LOG, new Date(), null, null, LogConstants.EVENT_SYSTEM_STOPPED_LOGGING , "Terminating log session for this node.",null);
		systemShutdownNotice = true;
	}
	
	/**
	 * @return true if the application server is about to go down.
	 */
	public boolean getSystemShutdownNotice() {
		return systemShutdownNotice;
	}
	
	/**
	 * @see org.ejbca.core.model.log.ILogDevice
	 */
	synchronized public void destructor() {
		// This could be called from several LogSession beans, but we only keep one instance..
		if (!isDestructorInvoked) {
			isDestructorInvoked = true;
		}
	}
	
	/**
	 * @see org.ejbca.core.model.log.ILogDevice
	 */
	public String getDeviceName() {
		return deviceName;
	}
	
	/**
	 * @see org.ejbca.core.model.log.ILogDevice
	 */
	public Properties getProperties() {
		return properties;
	}

	private IProtectedLogSessionLocal getProtectedLogSession() {
		try {
			if (protectedLogSession == null) {
				protectedLogSession = ((IProtectedLogSessionLocalHome) ServiceLocator.getInstance().getLocalHome(IProtectedLogSessionLocalHome.COMP_NAME)).create();
			}
			return protectedLogSession;
		} catch (Exception e) {
			throw new EJBException(e);
		}
	}

	/**
	 * @see org.ejbca.core.model.log.ILogDevice
	 */
	public boolean getAllowConfigurableEvents() {
		return allowConfigurableEvents;
	}

	
	/**
	 * @see org.ejbca.core.model.log.ILogDevice
	 */
	private ProtectedLogToken getProtectedLogToken() {
		if (protectedLogToken == null) {
			protectedLogToken = getProtectedLogSession().getProtectedLogToken(properties);
		}
		return protectedLogToken;
	}
	
	/**
	 * @see org.ejbca.core.model.log.ILogDevice
	 */
	synchronized public void log(Admin admininfo, int caid, int module, Date time, String username, X509Certificate certificate, int event, String comment, Exception exception) {
		// Is first LogEvent? Write Initiating Log Event
		if (isFirstLogEvent) {
			isFirstLogEvent = false;
			logInternal(internalAdmin, internalAdmin.getCaId(), LogConstants.MODULE_LOG, new Date(time.getTime()-1), null, null, LogConstants.EVENT_SYSTEM_INITILIZED_LOGGING, "Initiating log for this node.",null);
			//protectedLogActions.takeActions(IProtectedLogAction.CAUSE_TESTING);
		}
		if (!systemShutdownNotice || event == LogConstants.EVENT_SYSTEM_STOPPED_LOGGING) {
			logInternal(admininfo, caid, module, time, username, certificate, event, comment, exception);
		} else {
			logInternalOnShutDown(admininfo, caid, module, time, username, certificate, event, comment, exception);
		}
	}

	/**
	 * Implemenation of the log-protection algorithm.
	 * 
	 * Chains each new log-event together with last processed and any new event found in database.
	 */
	private void logInternal(Admin admininfo, int caid, int module, Date time, String username, X509Certificate certificate, int event, String comment, Exception exception) {
		// Convert exception to something loggable
		if (exception != null) {
			comment += ", Exception: " + exception.getMessage(); 
		}
		try {
			// Find nodes to link in
			ProtectedLogEventIdentifier[] linkedInEventIdentifiers = null;
			ArrayList linkedInEventIdentifiersCollection = new ArrayList(0);	// <ProtectedLogEventIdentifier>
			if (counter == 0) {
				// Find newest protected event in database to link in
				ProtectedLogEventIdentifier protectedLogEventIdentifier = null;
				protectedLogEventIdentifier = getProtectedLogSession().findNewestProtectedLogEventRow();
				if (protectedLogEventIdentifier != null) {
					linkedInEventIdentifiersCollection.add(protectedLogEventIdentifier);
				} else {
					// Database log is empty!
			    	log.error(intres.getLocalizedMessage("protectedlog.error.emptyorunprotected"));
					protectedLogActions.takeActions(IProtectedLogAction.CAUSE_EMPTY_LOG);
				}
			} else {
				// FInd all new events from other nodes in database to link in, if the right amount of time has passed since last time
				long now = System.currentTimeMillis();
				if (intensityOfSearchForLogEvents != -1000 && lastTimeOfSearchForLogEvents + intensityOfSearchForLogEvents < now) {
					ProtectedLogEventIdentifier[] protectedLogEventIdentifiers = null;
					protectedLogEventIdentifiers = getProtectedLogSession().findNewestProtectedLogEventsForAllOtherNodes(nodeGUID, lastTimeOfSearchForLogEvents - 50); // Have some marginal for processing time
					if (protectedLogEventIdentifiers != null) {
						for (int i=0; i<protectedLogEventIdentifiers.length; i++) {
							linkedInEventIdentifiersCollection.add(protectedLogEventIdentifiers[i]);
						}
					}
					lastTimeOfSearchForLogEvents = now;
				}
			}
			// Verify all events about to be linked in (except this nodes last event that is verified seperately
			ArrayList protectedLogEventIdentifiersToRemove = new ArrayList(0);	// <ProtectedLogEventIdentifier>
			if (!linkedInEventIdentifiersCollection.isEmpty()) {
				Iterator i = linkedInEventIdentifiersCollection.iterator();
				while (i.hasNext()) {
					ProtectedLogEventIdentifier protectedLogEventIdentifier = (ProtectedLogEventIdentifier) i.next();
					ProtectedLogEventRow protectedLogEventRow = getProtectedLogSession().getProtectedLogEventRow(protectedLogEventIdentifier);
					if (protectedLogEventRow == null ) {
				    	log.error(intres.getLocalizedMessage("protectedlog.error.logrowmissing", protectedLogEventIdentifier.getNodeGUID(),
				    			protectedLogEventIdentifier.getCounter()));
						protectedLogActions.takeActions(IProtectedLogAction.CAUSE_MISSING_LOGROW);
						protectedLogEventIdentifiersToRemove.add(protectedLogEventIdentifier);
						continue;
					}
					ProtectedLogToken protectedLogToken = getProtectedLogSession().getToken(protectedLogEventRow.getProtectionKeyIdentifier());
					if (protectedLogToken == null ) {
				    	log.error(intres.getLocalizedMessage("protectedlog.error.tokenmissing", protectedLogEventRow.getProtectionKeyIdentifier()));
						protectedLogActions.takeActions(IProtectedLogAction.CAUSE_MISSING_TOKEN);
						// Add for removal if the event fails verification
						protectedLogEventIdentifiersToRemove.add(protectedLogEventIdentifier);
						continue;
					}
					if ( !protectedLogToken.verify(protectedLogEventRow.getAsByteArray(false), protectedLogEventRow.getProtection())) {
				    	log.error(intres.getLocalizedMessage("protectedlog.error.logrowchanged", protectedLogEventIdentifier.getNodeGUID(),
				    			protectedLogEventIdentifier.getCounter()));
						protectedLogActions.takeActions(IProtectedLogAction.CAUSE_MODIFIED_LOGROW);
						// Add for removal if the event fails verification
						protectedLogEventIdentifiersToRemove.add(protectedLogEventIdentifier);
						continue;
					}
				}
			}
			Iterator iterator = protectedLogEventIdentifiersToRemove.iterator();
			while (iterator.hasNext()) {
				linkedInEventIdentifiersCollection.remove(iterator.next());
			}
			// Add previous ProtectedLogEventRow this node has produced, if any
			// Start by verifying that the last event in the database is correct, but only do this if sufficient time has passed since this was last verified
			if (counter != 0) {
				ProtectedLogEventIdentifier lastProtectedLogEventIdentifier = new ProtectedLogEventIdentifier(nodeGUID, counter-1);
				linkedInEventIdentifiersCollection.add(lastProtectedLogEventIdentifier);
				long now = System.currentTimeMillis();
				if (intensityOfSearchForOwnLogEvent != -1000 && lastTimeOfSearchForOwnLogEvent + intensityOfSearchForOwnLogEvent < now) {
					ProtectedLogEventRow protectedLogEventRow = getProtectedLogSession().getProtectedLogEventRow(lastProtectedLogEventIdentifier);
					if (protectedLogEventRow == null) {
				    	log.error(intres.getLocalizedMessage("protectedlog.error.logrowmissing", nodeGUID, counter-1));
						protectedLogActions.takeActions(IProtectedLogAction.CAUSE_MISSING_LOGROW);
					} else if (!Arrays.equals(protectedLogEventRow.calculateHash(), lastProtectedLogRowHash)) {
				    	log.error(intres.getLocalizedMessage("protectedlog.error.logrowchanged", nodeGUID, counter-1));
						protectedLogActions.takeActions(IProtectedLogAction.CAUSE_MODIFIED_LOGROW);
					}
					lastTimeOfSearchForOwnLogEvent = now;
				}
			}
			linkedInEventIdentifiers = (ProtectedLogEventIdentifier[]) linkedInEventIdentifiersCollection.toArray(new ProtectedLogEventIdentifier[0]);
			// Create a hash of the linked in nodes
			MessageDigest messageDigest = MessageDigest.getInstance(protectionHashAlgorithm, "BC");
			// Chain nodes with hash
			byte[] linkedInEventsHash = null;
			if (linkedInEventIdentifiers != null && linkedInEventIdentifiers.length != 0) {
				for (int i=0; i<linkedInEventIdentifiers.length; i++) {
					if (linkedInEventIdentifiers[i].equals(new ProtectedLogEventIdentifier(nodeGUID, counter-1))) {
						// Don't trust the database for this, use saved value
						messageDigest.update(lastProtectedLogRowHash);
					} else {
						messageDigest.update(getProtectedLogSession().getProtectedLogEventRow(linkedInEventIdentifiers[i]).calculateHash());
					}
				}
				linkedInEventsHash = messageDigest.digest();
			}
			String certificateSerialNumber = null;
			String certificateIssuerDN = null; 
			if (certificate != null) {
				certificateSerialNumber = certificate.getSerialNumber().toString(16);
				certificateIssuerDN = certificate.getIssuerDN().toString(); 
			}
			ProtectedLogEventRow protectedLogEventRow = new ProtectedLogEventRow(
					admininfo.getAdminType(), admininfo.getAdminData(), caid, module, time.getTime(), username, certificateSerialNumber, 
					certificateIssuerDN, event, comment, new ProtectedLogEventIdentifier(nodeGUID, counter), nodeIP, linkedInEventIdentifiers,
					linkedInEventsHash, protectionHashAlgorithm, getProtectedLogToken().getIdentifier(),
					getProtectedLogToken().getProtectionAlgorithm(), null);
			// Add protection to row depending on choosen intensity
			byte[] currentRowData = protectedLogEventRow.getAsByteArray(false);
			// Since the might be somewhat unsynched from different nodes 0 mean all rows.. 
			if (protectionIntensity == 0 || (lastTime + protectionIntensity) <= time.getTime() ) {
				protectedLogEventRow.setProtection(getProtectedLogToken().protect(currentRowData));
				lastTime = time.getTime();
			}
			getProtectedLogSession().addProtectedLogEventRow(protectedLogEventRow);
			lastProtectedLogRowHash = protectedLogEventRow.calculateHash();
			counter++;
		} catch (Exception e) {
        	log.error(intres.getLocalizedMessage("protectedlog.error.internallogerror"), e);
			protectedLogActions.takeActions(IProtectedLogAction.CAUSE_INTERNAL_ERROR);
			throw new EJBException(e);
		}
	}

	/**
	 * At this point we can no longer rely on beans to exist. We do our best to log as much as possible, unprotected.
	 * The admin has to manually "accept" these log-events on another node or when the server is back up using the CLI.
	 */
	private void logInternalOnShutDown(Admin admininfo, int caid, int module, Date time, String username, X509Certificate certificate, int event, String comment, Exception exception) {
		ProtectedLogToken protectedLogToken = new ProtectedLogToken();
		String certificateSerialNumber = null;
		String certificateIssuerDN = null; 
		if (certificate != null) {
			certificateSerialNumber = certificate.getSerialNumber().toString(16);
			certificateIssuerDN = certificate.getIssuerDN().toString(); 
		}
		ProtectedLogEventIdentifier[] linkedInEventIdentifiers = new ProtectedLogEventIdentifier[1];
		linkedInEventIdentifiers[0] = new ProtectedLogEventIdentifier(nodeGUID, counter-1);
		ProtectedLogEventRow protectedLogEventRow = new ProtectedLogEventRow(
				admininfo.getAdminType(), admininfo.getAdminData(), caid, module, time.getTime(), username, certificateSerialNumber, 
				certificateIssuerDN, event, comment, new ProtectedLogEventIdentifier(nodeGUID, counter), nodeIP, linkedInEventIdentifiers,
				lastProtectedLogRowHash, protectionHashAlgorithm, protectedLogToken.getIdentifier(),
				protectedLogToken.getProtectionAlgorithm(), null);
		try {
			getProtectedLogSession().addProtectedLogEventRow(protectedLogEventRow);
		} catch (Exception e) {
        	log.error(intres.getLocalizedMessage("protectedlog.error.logdropped",admininfo+" "+caid+" "+" "+module+" "+" "+time+" "+username+" "
					+certificate+" "+event+" "+comment+" "+exception, e.getMessage()));
			return;
		}
    	log.error(intres.getLocalizedMessage("protectedlog.error.logunprotected",admininfo+" "+caid+" "+" "+module+" "+" "+time+" "+username+" "
				+certificate+" "+event+" "+comment+" "+exception));
		lastProtectedLogRowHash = protectedLogEventRow.calculateHash();
		counter++;
	}

	/**
	 * @see org.ejbca.core.model.log.ILogDevice
	 */
	public byte[] export(Admin admin, Query query, String viewlogprivileges, String capriviledges, ILogExporter logexporter) throws IllegalQueryException, CADoesntExistsException, ExtendedCAServiceRequestException, IllegalExtendedCAServiceRequestException, ExtendedCAServiceNotActiveException {
		return null;
	}

	/**
	 * @see org.ejbca.core.model.log.ILogDevice
	 */
	public Collection query(Query query, String viewlogprivileges, String capriviledges) throws IllegalQueryException {
		log.debug(">query()");
		Collection ret = null;
		if (capriviledges == null || capriviledges.length() == 0 || !query.isLegalQuery()) {
			throw new IllegalQueryException();
		}
		String queryString = query.getQueryString();
	    //private final String LOGENTRYDATA_COL = "id, adminType, adminData, caid, module, time, username, certificateSNR, event"; "comment"; or "comment_"
		queryString = queryString.replaceAll("caid", "caId").replaceAll("event", "eventId").replaceAll("certificateSNR", "certificateSerialNumber");
		queryString = queryString.replaceAll("comment", "eventComment").replaceAll("time", "eventTime");
		String sql = "SELECT pk, adminType, adminData, caId, module, eventTime, username, certificateSerialNumber, eventId, eventComment from ProtectedLogData where ( "
		+ queryString + ") and (" + capriviledges + ")";
		if (StringUtils.isNotEmpty(viewlogprivileges)) {
			sql += " and (" + viewlogprivileges + ")";
		}
		log.debug("Query: "+sql);
		ret = getProtectedLogSession().performQuery(sql);
		return ret;
	} // query
}
