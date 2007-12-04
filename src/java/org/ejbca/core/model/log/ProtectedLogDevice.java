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
	
	private static final Logger log = Logger.getLogger(ProtectedLogDevice.class);

	private static final SecureRandom seeder = new SecureRandom();

	private static Admin internalAdmin = new Admin(Admin.TYPE_INTERNALUSER);

	private IProtectedLogSessionLocal protectedLogSession = null;
	
	/**
	 * A handle to the unique Singleton instance.
	 */
	private static ILogDevice instance;
	private static boolean isDestructorInvoked = false;

	private Properties properties;
	private int nodeGUID;
	private long counter;
	private byte[] lastProtectedLogRowHash = null;
	private long lastTime = 0;
	private long protectionIntensity = 0;
	private String nodeIP = "127.0.0.1";
	private ProtectedLogToken protectedLogToken = null;
	private String protectionHashAlgorithm = null;
	private boolean isFirstLogEvent = true;
	private ProtectedLogActions protectedLogActions = null;
	private boolean allowConfigurableEvents = false;
	private String deviceName = null;
	
	protected ProtectedLogDevice(Properties prop) throws Exception {
		properties = prop;
		deviceName = properties.getProperty("deviceName", "ProtectedLogDevice");
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
			log.warn("Using " + ProtectedLogExporter.CONF_DELETE_AFTER_EXPORT + "=true and "+CONFIG_PROTECTION_INTENSITY+" is not 0. "+
					"This is not safe in an environment where more than one node is running at the same time.");
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
	 * @see org.ejbca.core.model.log.ILogDevice
	 */
	synchronized public void destructor() {
		// This could be called from several LogSession beans, but we only keep one instance..
		if (!isDestructorInvoked) {
			isDestructorInvoked = true;
			log(internalAdmin, -1, 0, new Date(), null, null, LogConstants.EVENT_SYSTEM_STOPPED_LOGGING , "Terminating log session for this node.",null);
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
			logInternal(internalAdmin, -1, 0, new Date(time.getTime()-1), null, null, LogConstants.EVENT_SYSTEM_INITILIZED_LOGGING, "Initiating log for this node.",null);
			//protectedLogActions.takeActions(IProtectedLogAction.CAUSE_TESTING);
		}
		logInternal(admininfo, caid, module, time, username, certificate, event, comment, exception);
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
					protectedLogActions.takeActions(IProtectedLogAction.CAUSE_EMPTY_LOG);
				}
			} else {
				// FInd all new events from other nodes in database to link in
				ProtectedLogEventIdentifier[] protectedLogEventIdentifiers = null;
				protectedLogEventIdentifiers = getProtectedLogSession().findNewestProtectedLogEventsForAllOtherNodes(nodeGUID, lastTime - 60); // Have some marginal for processing time
				if (protectedLogEventIdentifiers != null) {
					for (int i=0; i<protectedLogEventIdentifiers.length; i++) {
						linkedInEventIdentifiersCollection.add(protectedLogEventIdentifiers[i]);
					}
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
						protectedLogActions.takeActions(IProtectedLogAction.CAUSE_MISSING_LOGROW);
						log.error("Could not link in " + protectedLogEventIdentifier.getNodeGUID() + " " + protectedLogEventIdentifier.getCounter());
						protectedLogEventIdentifiersToRemove.add(protectedLogEventIdentifier);
						continue;
					}
					ProtectedLogToken protectedLogToken = getProtectedLogSession().getToken(protectedLogEventRow.getProtectionKeyIdentifier());
					if (protectedLogToken == null ) {
						protectedLogActions.takeActions(IProtectedLogAction.CAUSE_MISSING_TOKEN);
						// Add for removal if the event fails verification
						protectedLogEventIdentifiersToRemove.add(protectedLogEventIdentifier);
						continue;
					}
					if ( !protectedLogToken.verify(protectedLogEventRow.getAsByteArray(false), protectedLogEventRow.getProtection())) {
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
			if (counter != 0) {
				ProtectedLogEventIdentifier lastProtectedLogEventIdentifier = new ProtectedLogEventIdentifier(nodeGUID, counter-1);
				linkedInEventIdentifiersCollection.add(lastProtectedLogEventIdentifier);
				ProtectedLogEventRow protectedLogEventRow = getProtectedLogSession().getProtectedLogEventRow(lastProtectedLogEventIdentifier);
				if (protectedLogEventRow == null) {
					protectedLogActions.takeActions(IProtectedLogAction.CAUSE_MISSING_LOGROW);
				} else if (!Arrays.equals(protectedLogEventRow.calculateHash(), lastProtectedLogRowHash)) {
					log.info(" ("+nodeGUID+"," + (counter-1)+") hash has changed in database, compared to hash kept in memory " + lastProtectedLogRowHash[0] + "... ");
					protectedLogActions.takeActions(IProtectedLogAction.CAUSE_MODIFIED_LOGROW);
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
			log.error("Internal logging error.", e);
			protectedLogActions.takeActions(IProtectedLogAction.CAUSE_INTERNAL_ERROR);
			throw new EJBException(e);
		}
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
