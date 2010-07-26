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

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.InputStream;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.net.URI;
import java.security.Key;
import java.security.KeyStore;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.Signature;
import java.security.cert.Certificate;
import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.Date;
import java.util.Iterator;
import java.util.List;

import javax.crypto.SecretKey;
import javax.ejb.EJB;
import javax.ejb.EJBException;
import javax.ejb.Stateless;
import javax.ejb.TransactionAttribute;
import javax.ejb.TransactionAttributeType;
import javax.persistence.EntityManager;
import javax.persistence.PersistenceContext;

import org.apache.log4j.Logger;
import org.ejbca.config.ProtectedLogConfiguration;
import org.ejbca.core.ejb.JNDINames;
import org.ejbca.core.ejb.ca.caadmin.CAAdminSessionLocal;
import org.ejbca.core.ejb.ca.sign.SignSessionLocal;
import org.ejbca.core.ejb.ca.store.CertificateStatus;
import org.ejbca.core.ejb.ca.store.CertificateStoreSessionLocal;
import org.ejbca.core.ejb.services.ServiceSessionLocal;
import org.ejbca.core.model.InternalResources;
import org.ejbca.core.model.SecConst;
import org.ejbca.core.model.ca.caadmin.CAInfo;
import org.ejbca.core.model.ca.catoken.CATokenOfflineException;
import org.ejbca.core.model.ca.crl.RevokedCertInfo;
import org.ejbca.core.model.log.Admin;
import org.ejbca.core.model.log.IProtectedLogAction;
import org.ejbca.core.model.log.IProtectedLogExportHandler;
import org.ejbca.core.model.log.IProtectedLogToken;
import org.ejbca.core.model.log.LogConstants;
import org.ejbca.core.model.log.LogEntry;
import org.ejbca.core.model.log.ProtectedLogActions;
import org.ejbca.core.model.log.ProtectedLogDevice;
import org.ejbca.core.model.log.ProtectedLogDummyExportHandler;
import org.ejbca.core.model.log.ProtectedLogEventIdentifier;
import org.ejbca.core.model.log.ProtectedLogEventRow;
import org.ejbca.core.model.log.ProtectedLogExportRow;
import org.ejbca.core.model.log.ProtectedLogExporter;
import org.ejbca.core.model.log.ProtectedLogToken;
import org.ejbca.core.model.log.ProtectedLogVerifier;
import org.ejbca.core.model.protect.TableVerifyResult;
import org.ejbca.core.model.services.ServiceConfiguration;
import org.ejbca.core.model.services.workers.ProtectedLogExportWorker;
import org.ejbca.core.model.services.workers.ProtectedLogVerificationWorker;
import org.ejbca.util.Base64;
import org.ejbca.util.CertTools;
import org.ejbca.util.JDBCUtil;
import org.ejbca.util.ManualUpdateCache;
import org.ejbca.util.StringTools;
import org.ejbca.util.TCPTool;

/**
 * The center of the Protected Log functionality. Most services used in this workflow are found here.
 *
 * @ejb.bean
 *   display-name="ProtectedLogSessionBean"
 *   name="ProtectedLogSession"
 *   jndi-name="ProtectedLogSession"
 *   local-jndi-name="ProtectedLogSessionLocal"
 *   view-type="both"
 *   type="Stateless"
 *   transaction-type="Container"
 *
 * @ejb.transaction type="Supports"
 * 
 * @weblogic.enable-call-by-reference True
 *
 * @ejb.env-entry
 * name="DataSource"
 * type="java.lang.String"
 * value="${datasource.jndi-name-prefix}${datasource.jndi-name}"
 *
 * @ejb.ejb-external-ref
 *   description="The ProtectedLogData entity bean"
 *   view-type="local"
 *   ref-name="ejb/ProtectedLogDataLocal"
 *   type="Entity"
 *   home="org.ejbca.core.ejb.log.ProtectedLogDataLocalHome"
 *   business="org.ejbca.core.ejb.log.ProtectedLogDataLocal"
 *   link="ProtectedLogData"
 *   
 * @ejb.ejb-external-ref
 *   description="The ProtectedLogTokenData entity bean"
 *   view-type="local"
 *   ref-name="ejb/ProtectedLogTokenDataLocal"
 *   type="Entity"
 *   home="org.ejbca.core.ejb.log.ProtectedLogTokenDataLocalHome"
 *   business="org.ejbca.core.ejb.log.ProtectedLogTokenDataLocal"
 *   link="ProtectedLogTokenData"
 *   
 * @ejb.ejb-external-ref
 *   description="The ProtectedLogExportData entity bean"
 *   view-type="local"
 *   ref-name="ejb/ProtectedLogExportDataLocal"
 *   type="Entity"
 *   home="org.ejbca.core.ejb.log.ProtectedLogExportDataLocalHome"
 *   business="org.ejbca.core.ejb.log.ProtectedLogExportDataLocal"
 *   link="ProtectedLogExportData"
 *   
 * @ejb.ejb-external-ref description="The Sign Session Bean"
 *   view-type="local"
 *   ref-name="ejb/RSASignSessionLocal"
 *   type="Session"
 *   home="org.ejbca.core.ejb.ca.sign.ISignSessionLocalHome"
 *   business="org.ejbca.core.ejb.ca.sign.ISignSessionLocal"
 *   link="RSASignSession"
 *   
 * @ejb.ejb-external-ref
 *   description="The CA Admin Session"
 *   view-type="local"
 *   ref-name="ejb/CAAdminSessionLocal"
 *   type="Session"
 *   home="org.ejbca.core.ejb.ca.caadmin.ICAAdminSessionLocalHome"
 *   business="org.ejbca.core.ejb.ca.caadmin.ICAAdminSessionLocal"
 *   link="CAAdminSession"
 *   
 * @ejb.home
 *   extends="javax.ejb.EJBHome"
 *   local-extends="javax.ejb.EJBLocalHome"
 *   local-class="org.ejbca.core.ejb.log.IProtectedLogSessionLocalHome"
 *   remote-class="org.ejbca.core.ejb.log.IProtectedLogSessionHome"
 *
 * @ejb.interface
 *   extends="javax.ejb.EJBObject"
 *   local-extends="javax.ejb.EJBLocalObject"
 *   local-class="org.ejbca.core.ejb.log.IProtectedLogSessionLocal"
 *   remote-class="org.ejbca.core.ejb.log.IProtectedLogSessionRemote"
 *
 * @jboss.method-attributes
 *   pattern = "get*"
 *   read-only = "true"
 *   
 * @jboss.method-attributes
 *   pattern = "verify*"
 *   read-only = "true"
 *   
 * @jboss.method-attributes
 *   pattern = "find*"
 *   read-only = "true"
 *   
 * @jonas.bean
 *   ejb-name="ProtectedLogSession"
 *
 * @deprecated
 */
@Stateless(mappedName = org.ejbca.core.ejb.JndiHelper.APP_JNDI_PREFIX + "ProtectedLogSessionRemote")
@TransactionAttribute(TransactionAttributeType.SUPPORTS)
public class ProtectedLogSessionBean implements ProtectedLogSessionLocal, ProtectedLogSessionRemote {

	private static final Logger log = Logger.getLogger(ProtectedLogSessionBean.class);
    /** Internal localization of logs and errors */
    private static final InternalResources intres = InternalResources.getInstance();

	private static Admin internalAdmin = new Admin(Admin.TYPE_INTERNALUSER);

    @PersistenceContext(unitName="ejbca")
    private EntityManager entityManager;

    @EJB
	private CAAdminSessionLocal caAdminSession;
	@EJB
	private CertificateStoreSessionLocal certificateStoreSession;
	@EJB
	private SignSessionLocal signSession;
	@EJB
	private ServiceSessionLocal serviceSession;

	/** Cache of log tokens, so we don't have to load a CA token or keystore every time.
	 * We can have this as static, because the protected log configuration is global for every CA node.
	 */
	private static IProtectedLogToken protectedLogTokenCache = null;
	private Certificate certificateCache = null;

	/**
	 * Persists a new token to the database.
	 * @ejb.interface-method view-type="both"
	 * @ejb.transaction type="Required"
	 */
	@TransactionAttribute(TransactionAttributeType.REQUIRED)
	public void addToken(IProtectedLogToken token) {
		log.trace(">addToken");
		try {
			int tokenType = token.getType();
			switch (tokenType) {
			case IProtectedLogToken.TYPE_CA:
				entityManager.persist(new ProtectedLogTokenData(token.getIdentifier(), tokenType, token.getTokenCertificate(), String.valueOf(token.getCAId())));
				break;
			case IProtectedLogToken.TYPE_NONE:
				entityManager.persist(new ProtectedLogTokenData(token.getIdentifier(), tokenType, token.getTokenCertificate(), String.valueOf(token.getCAId())));
				break;
			case IProtectedLogToken.TYPE_ASYM_KEY:
			case IProtectedLogToken.TYPE_SYM_KEY:
				ByteArrayOutputStream baos = new ByteArrayOutputStream();
				ObjectOutputStream oos = new ObjectOutputStream(baos);
				oos.writeObject(token.getTokenProtectionKey());
				oos.close();
				byte[] rawKeyData = encryptKeyData(baos.toByteArray(), token.getTokenCertificate());
				entityManager.persist(new ProtectedLogTokenData(token.getIdentifier(), tokenType, token.getTokenCertificate(), new String(Base64.encode(rawKeyData, false))));
				break;
			}
		} catch (Exception e) {
			log.error("", e);
			throw new EJBException(e);
		}
		log.trace("<addToken");
	}

	/**
	 * Fetch a existing token from the database. Caches the last found token.
	 * @return null if no token was found
	 * @ejb.interface-method view-type="both"
	 */
	public IProtectedLogToken getToken(int tokenIdentifier) {
		if (log.isTraceEnabled()) {
			log.trace(">getToken");
		}
		if (protectedLogTokenCache != null && protectedLogTokenCache.getIdentifier() == tokenIdentifier) {
			if (log.isTraceEnabled()) {
				log.trace("<getToken (from cache)");
			}
			return protectedLogTokenCache;
		}
		IProtectedLogToken protectedLogToken = null;
		try {
			ProtectedLogTokenData pltd = ProtectedLogTokenData.findByTokenIdentifier(entityManager, tokenIdentifier);
			if (pltd != null) {
				int tokenType = pltd.getTokenType();
				switch (tokenType) {
				case IProtectedLogToken.TYPE_CA:
					protectedLogToken = new ProtectedLogToken(new Integer(Integer.parseInt(pltd.getTokenReference())).intValue(), pltd.getTokenCertificate());
					break;
				case IProtectedLogToken.TYPE_NONE:
					protectedLogToken = new ProtectedLogToken();
					break;
				case IProtectedLogToken.TYPE_ASYM_KEY:
				case IProtectedLogToken.TYPE_SYM_KEY:
					byte[] rawKeyData = Base64.decode(pltd.getTokenReference().getBytes()); 
					ByteArrayInputStream bais = new ByteArrayInputStream(decryptKeyData(rawKeyData, pltd.getTokenCertificate()));
					ObjectInputStream ois = new ObjectInputStream(bais);
					Key key = (Key) ois.readObject();
					ois.close();
					if (key instanceof PrivateKey) {
						protectedLogToken = new ProtectedLogToken((PrivateKey) key, pltd.getTokenCertificate());
					} else {
						protectedLogToken = new ProtectedLogToken((SecretKey) key, pltd.getTokenCertificate());
					}
				}
			} else { 
				log.error(intres.getLocalizedMessage("protectedlog.error.tokennotfound", tokenIdentifier));
			}
		} catch (Exception e) {
			log.error("", e);
		}
		protectedLogTokenCache = protectedLogToken;
		log.trace("<getToken");
		return protectedLogToken;
	}

	/**
	 * Encrypt key-data with the issuers certificate.
	 */
	private byte[] encryptKeyData(byte[] data, Certificate certificate) throws Exception {
		log.trace(">encryptKeyData");
		// Use issuing CA for encryption
		int caid = CertTools.getIssuerDN(certificate).hashCode();
		log.trace("<encryptKeyData");
		return caAdminSession.encryptWithCA(caid, data);
	}

	/**
	 * Decrypt key-data with the issuers certificate.
	 */
	private byte[] decryptKeyData(byte[] data, Certificate certificate) throws Exception {
		log.trace("<decryptKeyData");
		// Use issuing CA for decryption
		int caid = CertTools.getIssuerDN(certificate).hashCode();
		log.trace("<decryptKeyData");
		return caAdminSession.decryptWithCA(caid, data);
	}

	/**
	 * Find and remove all the specified tokens.
	 * @ejb.interface-method view-type="both"
	 * @ejb.transaction type="RequiresNew"
	 */
	@TransactionAttribute(TransactionAttributeType.REQUIRES_NEW)
	public void removeTokens(Integer[] tokenIdentifiers) {
		log.trace(">removeTokens");
		for (int i=0; i<tokenIdentifiers.length; i++) {
			ProtectedLogTokenData pltd = ProtectedLogTokenData.findByTokenIdentifier(entityManager, tokenIdentifiers[i].intValue());
			if (pltd != null) {
				entityManager.remove(pltd);
			}
		}
		log.trace("<removeTokens");
	}

	/**
	 * Persists a new export to the database.
	 * @ejb.interface-method view-type="both"
	 * @ejb.transaction type="RequiresNew"
	 */
	@TransactionAttribute(TransactionAttributeType.REQUIRES_NEW)
	public void addExport(ProtectedLogExportRow protectedLogExportRow) {
		log.trace(">addExport");
		entityManager.persist(new ProtectedLogExportData(
				protectedLogExportRow.getTimeOfExport(), protectedLogExportRow.getExportEndTime(), protectedLogExportRow.getExportStartTime(),
				protectedLogExportRow.getLogDataHash(), protectedLogExportRow.getPreviosExportHash(), protectedLogExportRow.getCurrentHashAlgorithm(),
				protectedLogExportRow.getSignatureCertificateAsByteArray(), protectedLogExportRow.getDeleted(), protectedLogExportRow.getSignature()
				));
		log.trace("<addExport");
	}

	/**
	 * @return the newest export
	 * @ejb.interface-method view-type="both"
	 */
	public ProtectedLogExportRow getLastExport() {
		log.trace(">getLastExport");
		ProtectedLogExportRow protectedLogExportRow = null;
		Connection con = null;
		PreparedStatement ps = null;
		ResultSet rs = null;
		try {
			con = JDBCUtil.getDBConnection(JNDINames.DATASOURCE);
			String sql="SELECT * FROM ProtectedLogExportData ORDER BY exportEndTime DESC";
			ps = con.prepareStatement(sql);
			ps.setFetchSize(1);
			ps.setMaxRows(1);
			rs = ps.executeQuery();
			if (rs.next()) {
				protectedLogExportRow = new ProtectedLogExportRow(rs);
			}
		} catch (Exception e) {
			log.error("", e);
			throw new EJBException(e);
		} finally {
			JDBCUtil.close(con, ps, rs);
		}
		log.trace("<getLastExport");
		return protectedLogExportRow;
	}

	/**
	 * @return the last signed export
	 * @ejb.interface-method view-type="both"
	 */
	public ProtectedLogExportRow getLastSignedExport() {
		log.trace(">getLastSignedExport");
		ProtectedLogExportRow protectedLogExportRow = null;
		Connection con = null;
		PreparedStatement ps = null;
		ResultSet rs = null;
		try {
			con = JDBCUtil.getDBConnection(JNDINames.DATASOURCE);
			String sql="SELECT * FROM ProtectedLogExportData WHERE b64Signature IS NOT NULL ORDER BY exportEndTime DESC";
			ps = con.prepareStatement(sql);
			ps.setFetchSize(1);
			ps.setMaxRows(1);
			rs = ps.executeQuery();
			if (rs.next()) {
				protectedLogExportRow = new ProtectedLogExportRow(rs);
			}
		} catch (Exception e) {
			log.error("", e);
			throw new EJBException(e);
		} finally {
			JDBCUtil.close(con, ps, rs);
		}
		log.trace("<getLastSignedExport");
		return protectedLogExportRow;
	}

	/**
	 * Persist a new ProtectedLogEvent
	 * @ejb.interface-method view-type="both"
	 * @ejb.transaction type="Required"
	 */
	@TransactionAttribute(TransactionAttributeType.REQUIRED)
	public void addProtectedLogEventRow(ProtectedLogEventRow protectedLogEventRow) {
		if (log.isTraceEnabled()) {
			log.trace(">addProtectedLogEventRow: "+protectedLogEventRow.getEventIdentifier().getNodeGUID()+", "+protectedLogEventRow.getEventIdentifier().getCounter());
		}
		entityManager.persist(new ProtectedLogData(
				protectedLogEventRow.getAdminType(), protectedLogEventRow.getAdmindata(), protectedLogEventRow.getCaid(),
				protectedLogEventRow.getModule(), protectedLogEventRow.getEventTime(), protectedLogEventRow.getUsername(),
				protectedLogEventRow.getCertificateSerialNumber(), protectedLogEventRow.getCertificateIssuerDN(),
				protectedLogEventRow.getEventId(), protectedLogEventRow.getEventComment(),
				protectedLogEventRow.getEventIdentifier(), protectedLogEventRow.getNodeIP(),
				protectedLogEventRow.getLinkedInEventIdentifiers(), protectedLogEventRow.getLinkedInEventsHash(),
				protectedLogEventRow.getCurrentHashAlgorithm(), protectedLogEventRow.getProtectionKeyIdentifier(),
				protectedLogEventRow.getProtectionKeyAlgorithm(), protectedLogEventRow.getProtection()
		));
		if (log.isTraceEnabled()) {
			log.trace("<addProtectedLogEventRow");
		}
	}

	/**
	 * @return the requested ProtectedLogRow or null if not found
	 * @ejb.interface-method view-type="both"
	 */
	public ProtectedLogEventRow getProtectedLogEventRow(ProtectedLogEventIdentifier identifier) {
		if (log.isTraceEnabled()) {
			log.trace(">getProtectedLogEventRow: "+identifier.getNodeGUID()+", "+identifier.getCounter());
		}
		if (identifier == null) {
			return null;
		}
		ProtectedLogData pld = ProtectedLogData.findByNodeGUIDandCounter(entityManager, identifier.getNodeGUID(), identifier.getCounter());
		if (pld == null) {
			if (log.isDebugEnabled()) {
				log.debug("Can not find logEventRow: "+identifier.getNodeGUID()+", "+identifier.getCounter());
			}
			return null;
		}
		log.trace("<getProtectedLogEventRow");
		return pld.toProtectedLogEventRow();
	}

	/**
	 * Find the newest event for all nodes, except the specified node.
	 * 
	 * @ejb.interface-method view-type="both"
	 */
	public ProtectedLogEventIdentifier[] findNewestProtectedLogEventsForAllOtherNodes(int nodeToExclude, long newerThan) {
		if (log.isTraceEnabled()) {
			log.trace(">findNewestProtectedLogEventsForAllOtherNodes");
		}
		if (newerThan < 0) {
			newerThan = 0;
		}
		ProtectedLogEventRow[] protectedLogEventRows = findNewestProtectedLogEventsForAllOtherNodesInternal(nodeToExclude, newerThan);
		ProtectedLogEventIdentifier[] protectedLogEventIdentifiers = null;
		if (protectedLogEventRows != null) {
			protectedLogEventIdentifiers = new ProtectedLogEventIdentifier[protectedLogEventRows.length];
			for (int i=0; i<protectedLogEventRows.length; i++) {
				protectedLogEventIdentifiers[i] = protectedLogEventRows[i].getEventIdentifier(); 
			}
		}
		if (log.isTraceEnabled()) {
			log.trace("<findNewestProtectedLogEventsForAllOtherNodes");
		}
		return protectedLogEventIdentifiers;
	}

	/**
	 * Find the newest ProtectedLogEvent for all nodes except one, that have an eventTime newer than the requested.
	 */
	private ProtectedLogEventRow[] findNewestProtectedLogEventsForAllOtherNodesInternal(int nodeToExclude, long newerThan) {
		if (log.isTraceEnabled()) {
			log.trace(">findNewestProtectedLogEventsForAllOtherNodesInternal");
		}
		// TODO: Double check the algo on this one to make it more efficient
		ProtectedLogEventRow[] protectedLogEventRows = null;
		Collection<ProtectedLogData> protectedLogDatas = ProtectedLogData.findNewProtectedLogEvents(entityManager, nodeToExclude, newerThan);
		ArrayList<ProtectedLogEventRow> protectedLogEventRowArrayList = new ArrayList<ProtectedLogEventRow>();
		Iterator<ProtectedLogData> i = protectedLogDatas.iterator();
		while (i.hasNext()) {
			ProtectedLogData protectedLogDataLocal = i.next();
			boolean addProtectedLogEventRow = true;
			ProtectedLogEventRow protectedLogEventRowToRemove = null;
			Iterator<ProtectedLogEventRow> j = protectedLogEventRowArrayList.iterator();
			while (j.hasNext()) {
				ProtectedLogEventRow protectedLogEventRow = (ProtectedLogEventRow) j.next();
				if (protectedLogDataLocal.getNodeGUID() == protectedLogEventRow.getEventIdentifier().getNodeGUID()) {
					if (protectedLogDataLocal.getEventTime() > protectedLogEventRow.getEventTime()) {
						// Replace if in array and newer (added later)
						protectedLogEventRowToRemove = protectedLogEventRow;
						break;
					} else {
						// Skip if in array and older
						addProtectedLogEventRow = false;
					}
				}
			}
			if (protectedLogEventRowToRemove != null) {
				protectedLogEventRowArrayList.remove(protectedLogEventRowToRemove);
				protectedLogEventRowToRemove = null;
			}
			if (addProtectedLogEventRow) {
				ProtectedLogEventRow newProtectedLogEventRow = protectedLogDataLocal.toProtectedLogEventRow();
				protectedLogEventRowArrayList.add(newProtectedLogEventRow);
			}
			protectedLogEventRows = (ProtectedLogEventRow[]) protectedLogEventRowArrayList.toArray(new ProtectedLogEventRow[0]);
		}
		if (log.isTraceEnabled()) {
			log.trace("<findNewestProtectedLogEventsForAllOtherNodesInternal");
		}
		return protectedLogEventRows;
	}

	/**
	 * @return the identifier of the newest protected ProtectedLogEvent
	 * @ejb.interface-method view-type="both"
	 */
	public ProtectedLogEventIdentifier findNewestProtectedLogEventRow(int nodeGUID) {
		if (log.isTraceEnabled()) {
			log.trace(">findNewestProtectedLogEventRow");
		}
		ProtectedLogEventIdentifier protectedLogEventIdentifier = null;
		Connection con = null;
		PreparedStatement ps = null;
		ResultSet rs = null;
		try {
			con = JDBCUtil.getDBConnection(JNDINames.DATASOURCE);
			String sql="SELECT nodeGUID, counter FROM ProtectedLogData WHERE b64Protection IS NOT NULL AND nodeGUID=? ORDER BY eventTime DESC";
			ps = con.prepareStatement(sql);
			ps.setInt(1, nodeGUID);
			ps.setFetchSize(1);
			ps.setMaxRows(1);
			rs = ps.executeQuery();
			if (rs.next()) {
				protectedLogEventIdentifier = new ProtectedLogEventIdentifier(rs.getInt(1), rs.getInt(2));
			}
		} catch (Exception e) {
			log.error("", e);
			throw new EJBException(e);
		} finally {
			JDBCUtil.close(con, ps, rs);
		}
		if (log.isTraceEnabled()) {
			log.trace("<findNewestProtectedLogEventRow");
		}
		return protectedLogEventIdentifier;
	}

	/**
	 * @return the identifier of the newest ProtectedLogEvent, protected or unprotected
	 * @ejb.interface-method view-type="both"
	 */
	public ProtectedLogEventIdentifier findNewestLogEventRow(int nodeGUID) {
		if (log.isTraceEnabled()) {
			log.trace(">findNewestLogEventRow");
		}
		ProtectedLogEventIdentifier protectedLogEventIdentifier = null;
		Connection con = null;
		PreparedStatement ps = null;
		ResultSet rs = null;
		try {
			con = JDBCUtil.getDBConnection(JNDINames.DATASOURCE);
			String sql="SELECT nodeGUID, counter FROM ProtectedLogData WHERE nodeGUID=? ORDER BY eventTime DESC";
			ps = con.prepareStatement(sql);
			ps.setInt(1, nodeGUID);
			ps.setFetchSize(1);
			ps.setMaxRows(1);
			rs = ps.executeQuery();
			if (rs.next()) {
				protectedLogEventIdentifier = new ProtectedLogEventIdentifier(rs.getInt(1), rs.getInt(2));
				if (log.isDebugEnabled()) {
					log.debug("Found a ProtectedLogEventIdentifier with GUID "+protectedLogEventIdentifier.getNodeGUID()+", and counter "+protectedLogEventIdentifier.getCounter());
				}
			}
		} catch (Exception e) {
			log.error("", e);
			throw new EJBException(e);
		} finally {
			JDBCUtil.close(con, ps, rs);
		}
		if (log.isTraceEnabled()) {
			log.trace("<findNewestLogEventRow");
		}
		return protectedLogEventIdentifier;
	}

	/**
	 * @ejb.interface-method view-type="both"
	 */
	public ProtectedLogEventIdentifier findNewestProtectedLogEventRow() {
		return findNewestProtectedLogEventRow(true);
	}

	/**
	 * @param search for protected events if true or unprotected if not
	 * @return the identifier of the newest ProtectedLogEvent
	 * @ejb.interface-method view-type="both"
	 */
	public ProtectedLogEventIdentifier findNewestProtectedLogEventRow(boolean isProtected) {
		if (log.isTraceEnabled()) {
			log.trace(">findNewestProtectedLogEventRow: "+isProtected);
		}
		ProtectedLogEventIdentifier protectedLogEventIdentifier = null;
		Connection con = null;
		PreparedStatement ps = null;
		ResultSet rs = null;
		try {
			con = JDBCUtil.getDBConnection(JNDINames.DATASOURCE);
			String sql="SELECT nodeGUID, counter FROM ProtectedLogData WHERE b64Protection IS "+(isProtected ? "NOT" : "")+" NULL ORDER BY eventTime DESC";
			ps = con.prepareStatement(sql);
			ps.setFetchSize(1);
			ps.setMaxRows(1);
			rs = ps.executeQuery();
			if (rs.next()) {
				protectedLogEventIdentifier = new ProtectedLogEventIdentifier(rs.getInt(1), rs.getInt(2));
			}
		} catch (Exception e) {
			log.error("", e);
			throw new EJBException(e);
		} finally {
			JDBCUtil.close(con, ps, rs);
		}
		if (log.isTraceEnabled()) {
			log.trace("<findNewestProtectedLogEventRow");
		}
		return protectedLogEventIdentifier;
	}

	/**
	 * Find the oldest log-event, protected or unprotected
	 * @ejb.interface-method view-type="both"
	 */
	public ProtectedLogEventIdentifier findOldestProtectedLogEventRow() {
		log.trace(">findOldestProtectedLogEventRow");
		ProtectedLogEventIdentifier protectedLogEventIdentifier = null;
		Connection con = null;
		PreparedStatement ps = null;
		ResultSet rs = null;
		try {
			con = JDBCUtil.getDBConnection(JNDINames.DATASOURCE);
			String sql="SELECT nodeGUID, counter FROM ProtectedLogData ORDER BY eventTime ASC";
			ps = con.prepareStatement(sql);
			ps.setFetchSize(1);
			ps.setMaxRows(1);
			rs = ps.executeQuery();
			if (rs.next()) {
				protectedLogEventIdentifier = new ProtectedLogEventIdentifier(rs.getInt(1), rs.getInt(2));
			}
		} catch (Exception e) {
			log.error("", e);
			throw new EJBException(e);
		} finally {
			JDBCUtil.close(con, ps, rs);
		}
		log.trace("<findOldestProtectedLogEventRow");
		return protectedLogEventIdentifier;
	}


	/**
	 * @return all different nodeGUID that exist between the requested times
	 * @ejb.interface-method view-type="both"
	 */
	public Integer[] getNodeGUIDs(long exportStartTime, long exportEndTime) {
		log.trace(">getNodeGUIDs");
		ArrayList<Integer> nodes = new ArrayList<Integer>();
		Connection con = null;
		PreparedStatement ps = null;
		ResultSet rs = null;
		try {
			con = JDBCUtil.getDBConnection(JNDINames.DATASOURCE);
			String sql="SELECT nodeGUID FROM ProtectedLogData WHERE eventTime >= ? AND eventTime < ? GROUP BY nodeGUID";
			ps = con.prepareStatement(sql);
			ps.setLong(1, exportStartTime);
			ps.setLong(2, exportEndTime);
			rs = ps.executeQuery();
			while (rs.next()) {
				nodes.add(rs.getInt(1));
			}
		} catch (Exception e) {
			log.error("", e);
			throw new EJBException(e);
		} finally {
			JDBCUtil.close(con, ps, rs);
		}
		log.trace("<getNodeGUIDs");
		return (Integer[]) nodes.toArray();
	}

	/**
	 * @return all different nodeGUID that exist
	 * @ejb.interface-method view-type="both"
	 */
	public Integer[] getAllNodeGUIDs() {
		log.trace(">getAllNodeGUIDs");
		ArrayList<Integer> nodes = new ArrayList<Integer>();
		Connection con = null;
		PreparedStatement ps = null;
		ResultSet rs = null;
		try {
			con = JDBCUtil.getDBConnection(JNDINames.DATASOURCE);
			String sql="SELECT nodeGUID FROM ProtectedLogData GROUP BY nodeGUID";
			ps = con.prepareStatement(sql);
			rs = ps.executeQuery();
			while (rs.next()) {
				nodes.add(rs.getInt(1));
			}
		} catch (Exception e) {
			log.error("", e);
			throw new EJBException(e);
		} finally {
			JDBCUtil.close(con, ps, rs);
		}
		log.trace("<getAllNodeGUIDs");
		return (Integer[]) nodes.toArray();
	}

	/**
	 * Find all nodeGUIDs where all log events are unprotected.
	 * @ejb.interface-method view-type="both"
	 */
	public Integer[] getFullyUnprotectedNodeGUIDs() {
		log.trace(">getFullyUnprotectedNodeGUIDs");
		ArrayList<Integer> nodes = new ArrayList<Integer>();
		Connection con = null;
		PreparedStatement ps = null;
		ResultSet rs = null;
		try {
			con = JDBCUtil.getDBConnection(JNDINames.DATASOURCE);
			String sql="SELECT nodeGUID FROM ProtectedLogData WHERE b64Protection IS NULL GROUP BY nodeGUID";
			ps = con.prepareStatement(sql);
			rs = ps.executeQuery();
			while (rs.next()) {
				nodes.add(rs.getInt(1));
			}
		} catch (Exception e) {
			log.error("", e);
			throw new EJBException(e);
		} finally {
			JDBCUtil.close(con, ps, rs);
		}
		log.trace("<getFullyUnprotectedNodeGUIDs");
		return (Integer[]) nodes.toArray(new Integer[0]);
	}

	/**
	 * @return at most fetchSize legevents between the specified times, oldest first 
	 * @ejb.interface-method view-type="both"
	 */
	public ProtectedLogEventRow[] findNextProtectedLogEventRows(long exportStartTime, long exportEndTime, int fetchSize) {
		log.trace(">findNextProtectedLogEventRows");
		ArrayList<ProtectedLogEventRow> protectedLogEventRows = new ArrayList<ProtectedLogEventRow>();
		Connection con = null;
		PreparedStatement ps = null;
		ResultSet rs = null;
		try {
			con = JDBCUtil.getDBConnection(JNDINames.DATASOURCE);
			// This sql might loose an event between calls if two times are equal
			String sql="SELECT * FROM ProtectedLogData WHERE eventTime >= ? AND eventTime <= ? ORDER BY eventTime ASC";
			ps = con.prepareStatement(sql);
			ps.setLong(1, exportStartTime);
			ps.setLong(2, exportEndTime);
			ps.setFetchSize(fetchSize+1);
			ps.setMaxRows(fetchSize*2); // No more than this at the time..
			rs = ps.executeQuery();
			int count = 0;
			long lastTime = 0;
			while (rs.next()) {
				ProtectedLogEventRow protectedLogEventRow = new ProtectedLogEventRow(rs);
				count++;
				if (count > fetchSize && protectedLogEventRow.getEventTime() != lastTime) {
					break;
				}
				protectedLogEventRows.add(protectedLogEventRow);
				lastTime = protectedLogEventRow.getEventTime();
			}
		} catch (Exception e) {
			log.error("", e);
			throw new EJBException(e);
		} finally {
			JDBCUtil.close(con, ps, rs);
		}
		log.trace("<findNextProtectedLogEventRows");
		return (ProtectedLogEventRow[]) protectedLogEventRows.toArray();
	}

	/**
	 * Deletes all log events until the reqeusted time
	 * @ejb.interface-method view-type="both"
	 * @ejb.transaction type="RequiresNew"
	 */
	@TransactionAttribute(TransactionAttributeType.REQUIRES_NEW)
	public void removeAllUntil(long exportEndTime) {
		log.trace(">removeAllUntil");
		Connection con = null;
		PreparedStatement ps = null;
		try {
			con = JDBCUtil.getDBConnection(JNDINames.DATASOURCE);
			String sql="DELETE FROM ProtectedLogData WHERE eventTime < ?";
			ps = con.prepareStatement(sql);
			ps.setLong(1, exportEndTime);
			ps.executeUpdate();
		} catch (Exception e) {
			log.error("", e);
			throw new EJBException(e);
		} finally {
			JDBCUtil.close(con, ps, null);
		}
		log.trace("<removeAllUntil");
	}

	/**
	 * Testing function. Removes all log-events belonging to a nodeGUID.
	 * @ejb.interface-method view-type="both"
	 * @ejb.transaction type="RequiresNew"
	 */
	@TransactionAttribute(TransactionAttributeType.REQUIRES_NEW)
	public void removeNodeChain(int nodeGUID) {
		log.trace(">removeNodeChain");
		Connection con = null;
		PreparedStatement ps = null;
		try {
			con = JDBCUtil.getDBConnection(JNDINames.DATASOURCE);
			String sql="DELETE FROM ProtectedLogData WHERE nodeGUID = ?";
			ps = con.prepareStatement(sql);
			ps.setInt(1, nodeGUID);
			ps.executeUpdate();
		} catch (Exception e) {
			log.error("", e);
			throw new EJBException(e);
		} finally {
			JDBCUtil.close(con, ps, null);
		}
		log.trace("<removeNodeChain");
	}

	/**
	 * Roll back the export table to the last one with the delete-flag set. This will remove all the export if none has the delet-flag set.
	 * @ejb.interface-method view-type="both"
	 */
	public boolean removeAllExports(boolean removeDeletedToo) {
		log.trace(">removeAllExports");
		Connection con = null;
		PreparedStatement ps = null;
		try {
			con = JDBCUtil.getDBConnection(JNDINames.DATASOURCE);
			String sql="DELETE FROM ProtectedLogExportData"+(removeDeletedToo ? "":" WHERE deleted=0");
			ps = con.prepareStatement(sql);
			ps.executeUpdate();
		} catch (Exception e) {
			log.error("", e);
			return false;
		} finally {
			JDBCUtil.close(con, ps, null);
		}
		log.trace("<removeAllExports");
		return true;
	}

	/**
	 * Retrieve a list of token the has been used before, but not after the request time.
	 * @ejb.interface-method view-type="both"
	 */
	public Integer[] findTokenIndentifiersUsedOnlyUntil(long exportEndTime) {
		log.trace(">findTokenIndentifiersUsedOnlyUntil");
		ArrayList<Integer> protectionKeyIdentifiers = new ArrayList<Integer>();
		Connection con = null;
		PreparedStatement ps = null;
		ResultSet rs = null;
		try {
			con = JDBCUtil.getDBConnection(JNDINames.DATASOURCE);
			String sql="SELECT protectionKeyIdentifier FROM ProtectedLogData WHERE eventTime < ? GROUP BY protectionKeyIdentifier";
			ps = con.prepareStatement(sql);
			ps.setLong(1, exportEndTime);
			rs = ps.executeQuery();
			while (rs.next()) {
				protectionKeyIdentifiers.add(new Integer(rs.getInt(1)));
			}
			sql="SELECT protectionKeyIdentifier FROM ProtectedLogData WHERE eventTime >= ? GROUP BY protectionKeyIdentifier";
			ps = con.prepareStatement(sql);
			ps.setLong(1, exportEndTime);
			rs = ps.executeQuery();
			while (rs.next()) {
				if (protectionKeyIdentifiers.contains(new Integer(rs.getInt(1)))) {
					protectionKeyIdentifiers.remove(new Integer(rs.getInt(1)));
				}
			}
		} catch (Exception e) {
			log.error("", e);
			throw new EJBException(e);
		} finally {
			JDBCUtil.close(con, ps, rs);
		}
		log.trace("<findTokenIndentifiersUsedOnlyUntil");
		return (Integer[]) protectionKeyIdentifiers.toArray(new Integer[0]);
	}

	/**
	 * Verifies that the certificate was valid at the time of signing and that the signature was made by the owner of this certificate.
	 * @ejb.interface-method view-type="both"
	 */
	public boolean verifySignature(byte[] data, byte[] signature, Certificate certificate, long timeOfSigning) {
		log.trace(">verifySignature");
		boolean verified = false;
		if (signature == null || data == null) {
			return false;
		}
		if (!verifyCertificate(certificate, timeOfSigning)) {
			return false;
		}
		try {
			// Verify signature of data
			Signature signer = Signature.getInstance(CertTools.getSignatureAlgorithm(certificate), "BC");
			signer.initVerify(certificate.getPublicKey());
			signer.update(data);
			verified = signer.verify(signature);
		} catch (Exception e) {
			log.error("", e);
		}
		if (log.isTraceEnabled()) {
			log.trace("<verifySignature returns " + verified);
		}
		return verified;
	}

	/**
	 * Verifies that the certificate was valid at the specified time
	 * @ejb.interface-method view-type="both"
	 */
	public boolean verifyCertificate(Certificate certificate, long timeOfUse) {
		if (log.isTraceEnabled()) {
			log.trace("<verifyCertificate");
		}
		boolean verified = false;
		try {
			// Verify that this is a certificate signed by a known CA
			if (certificateCache != null && certificate != null && Arrays.equals(certificateCache.getEncoded(), certificate.getEncoded())) {
				// We checked the signature last time, so it's ok.
			} else {
				int caid = CertTools.getIssuerDN(certificate).hashCode();
				CAInfo caInfo = caAdminSession.getCAInfo(new Admin(Admin.TYPE_INTERNALUSER), caid);
				CertTools.verify(certificate, caInfo.getCertificateChain());
			}
			// Verify that the certificate is valid
			CertTools.checkValidity(certificate, new Date(timeOfUse));
			// Verify that the cert wasn't revoked
			CertificateStatus revinfo = certificateStoreSession.getStatus(CertTools.getIssuerDN(certificate), CertTools.getSerialNumber(certificate));
			if (revinfo == null) {
				return false;	// Certificate missing
			} else if (revinfo.revocationReason  != RevokedCertInfo.NOT_REVOKED && revinfo.revocationDate.getTime() <= timeOfUse) {
				return false;	// Certificate was revoked
			}
			verified = true;
		} catch (Exception e) {
			log.error("",e);
		}
		if (log.isTraceEnabled()) {
			log.trace("<verifyCertificate returns " + verified);
		}
		return verified;
	}

	/**
	 * Reservers a slot in the export table.
	 * ejb.interface-method view-type="both"
	 * @ejb.transaction type="RequiresNew"
	 */
	@TransactionAttribute(TransactionAttributeType.REQUIRES_NEW)
	private ProtectedLogExportRow reserveExport(long atLeastThisOld) {
		log.trace(">reserveExport");
		ProtectedLogExportRow protectedLogExportRow = getLastSignedExport();
		ProtectedLogExportRow unProtectedLogExportRow = getLastExport();
		if (unProtectedLogExportRow != null) {
			if (!unProtectedLogExportRow.equals(protectedLogExportRow)) {
	        	log.info(intres.getLocalizedMessage("protectedlog.abstainexport"));
				return null;
			}
			if (!verifySignature(protectedLogExportRow.getAsByteArray(false), protectedLogExportRow.getSignature(),
					protectedLogExportRow.getSignatureCertificate(), protectedLogExportRow.getTimeOfExport())) {
	        	log.error(intres.getLocalizedMessage("protectedlog.error.invalidlastexport"));
				return null;
			}
		}
		// exportStartTime (oldest) is 0 or last exportEndTime
		long exportStartTime = 0;
		if (protectedLogExportRow != null) {
			exportStartTime = protectedLogExportRow.getExportEndTime() + 1;
		}
		long now = new Date().getTime();
		long exportEndTime = new Date().getTime();
		if (exportEndTime > now - atLeastThisOld) {
			exportEndTime = now - atLeastThisOld;
		}
		// Make sure all events before exportEndTime (the newest) are protected. If not, the
		// exportEndTime has to be adjusted until they are.
		Integer[] nodeGUIDs = getNodeGUIDs(exportStartTime, exportEndTime);
		for (int i=0; i<nodeGUIDs.length; i++) {
			//log.debug("Found " + nodeGUIDs[i] + "..");
			ProtectedLogEventIdentifier newestProtectedLogEventIdentifier = findNewestProtectedLogEventRow(nodeGUIDs[i]);
			if (newestProtectedLogEventIdentifier == null) {
	        	log.error(intres.getLocalizedMessage("protectedlog.error.unprotectednode", nodeGUIDs[i]));
				return null;
			}
			ProtectedLogEventRow newestProtectedLogEventRow = getProtectedLogEventRow(newestProtectedLogEventIdentifier);
			if (newestProtectedLogEventRow == null) {
	        	log.error(intres.getLocalizedMessage("protectedlog.error.couldnotfetch",
	        			newestProtectedLogEventIdentifier.getNodeGUID(), newestProtectedLogEventIdentifier.getCounter()));
				return null;
			}
			// If the latest signed event for a node isn't an stop-event we need to take the eventTime into account
			long currentTime = newestProtectedLogEventRow.getEventTime();
			if (newestProtectedLogEventRow.getEventId() != LogConstants.EVENT_SYSTEM_STOPPED_LOGGING && currentTime < exportEndTime) {
				exportEndTime = currentTime;
			}
			// Since this is now the newest event, we are going to use it's token or issuing CA-token. We want to know if it's has one..
			IProtectedLogToken plt = getToken(newestProtectedLogEventRow.getProtectionKeyIdentifier());
			if (plt == null) {
	        	log.error(intres.getLocalizedMessage("protectedlog.error.notoken",
	        			newestProtectedLogEventIdentifier.getNodeGUID(), newestProtectedLogEventIdentifier.getCounter()));
				return null;
			}
			// ...and that the token is working as supposed to.
			byte[] dummy = "testing if token is working".getBytes();
			if (plt.getType() == IProtectedLogToken.TYPE_CA && plt.protect(dummy) == null) {
	        	String iMsg = intres.getLocalizedMessage("protectedlog.error.tokennotworking",
	        			newestProtectedLogEventRow.getProtectionKeyIdentifier());
	        	log.error(iMsg);
				throw new EJBException(iMsg);
			}
			if (plt.getType() != IProtectedLogToken.TYPE_CA) {
				// If it is a soft token we need to verify that is issuing CA is online.
				Certificate cert = plt.getTokenCertificate();
				int caId = CertTools.getIssuerDN(cert).hashCode();
				try {
					signSession.signData(dummy, caId, SecConst.CAKEYPURPOSE_CERTSIGN);
				} catch (Exception e) {
		        	String iMsg = intres.getLocalizedMessage("protectedlog.error.canotworking", caId);
		        	log.error(iMsg);
					throw new EJBException(iMsg);
				}
			}
		}
		try {
			entityManager.persist(new ProtectedLogExportData(0, exportEndTime, exportStartTime, null, null, null, null, false, null));
			log.trace("<reserveExport");
			return getLastExport();
		} catch (Exception e) {
			log.error("", e);
			throw new EJBException(e);
		}
	}

	/**
	 * Either completes the reserved export if success if true or removes it. 
	 * ejb.interface-method view-type="both"
	 * @ejb.transaction type="RequiresNew"
	 */
	//Private... @TransactionAttribute(TransactionAttributeType.REQUIRES_NEW)
	private void completeExport(ProtectedLogExportRow protectedLogExportRow, boolean success) {
		log.trace(">completeExport");
		try {
			ProtectedLogExportData protectedLogExportData = ProtectedLogExportData.findByExportStartTime(entityManager, protectedLogExportRow.getExportStartTime());
			if (success) {
				protectedLogExportData.setTimeOfExport(protectedLogExportRow.getTimeOfExport());
				protectedLogExportData.setLogDataHash(protectedLogExportRow.getLogDataHash());
				protectedLogExportData.setPreviosExportHash(protectedLogExportRow.getPreviosExportHash());
				protectedLogExportData.setCurrentHashAlgorithm(protectedLogExportRow.getCurrentHashAlgorithm());
				protectedLogExportData.setSignatureCertificate(protectedLogExportRow.getSignatureCertificateAsByteArray());
				protectedLogExportData.setDeleted(protectedLogExportRow.getDeleted());
				protectedLogExportData.setSignature(protectedLogExportRow.getSignature());
			} else {
				entityManager.remove(protectedLogExportData);
			}
		} catch (Exception e) {
			log.error("", e);
			throw new EJBException(e);
		}
		log.trace("<completeExport");
	}

	/**
	 * Perform a query and convert to a Collection of LogEntry
	 * @ejb.interface-method view-type="both"
	 * @ejb.transaction type="Required"
	 */
	@TransactionAttribute(TransactionAttributeType.REQUIRED)
	public Collection performQuery(String sqlQuery, int maxResults) {
		log.trace(">performQuery");
		Connection con = null;
		PreparedStatement ps = null;
		ResultSet rs = null;
		try {
			// Construct SQL query.
			con = JDBCUtil.getDBConnection(JNDINames.DATASOURCE);
			ps = con.prepareStatement(sqlQuery);
			//ps.setFetchDirection(ResultSet.FETCH_REVERSE);
			ps.setFetchSize(maxResults + 1);
			// Execute query.
			rs = ps.executeQuery();
			// Assemble result.
			ArrayList<LogEntry> returnval = new ArrayList<LogEntry>();
			while (rs.next() && returnval.size() <= maxResults) {
				// Use pk 0
				LogEntry data = new LogEntry(0, rs.getInt(2), rs.getString(3), rs.getInt(4), rs.getInt(5), new Date(rs.getLong(6)), rs.getString(7), 
						rs.getString(8), rs.getInt(9), rs.getString(10));
				// Verify each result
				String verified = TableVerifyResult.VERIFY_FAILED_MSG;
				int result = verifyProtectedLogEventRow(ProtectedLogData.findById(entityManager, rs.getString(1)).toProtectedLogEventRow(), true);
				if (result == 1) {
					verified = TableVerifyResult.VERIFY_SUCCESS_MSG;
				} else if (result == 0) {
					verified = TableVerifyResult.VERIFY_UNDETERMINED_MSG;
				}
				data.setVerifyResult(verified);
				returnval.add(data);
			}
			log.trace("<performQuery");
			return returnval;
		} catch (Exception e) {
			throw new EJBException(e);
		} finally {
			JDBCUtil.close(con, ps, rs);
		}
	}

	/**
	 * Iterates forward in time, verifying each hash of the previous event until a signature is reached which is verified.
	 * @return -1 on failure, 0 if undetermined, 1 if successful
	 * @ejb.interface-method view-type="both"
	 * @ejb.transaction type="Required"
	 */
	@TransactionAttribute(TransactionAttributeType.REQUIRED)
	public int verifyProtectedLogEventRow(ProtectedLogEventRow protectedLogEventRow, boolean checkVerifiedSteps) {
		if (log.isTraceEnabled()) {
			log.trace(">verifyProtectedLogEventRow");
		}
		int maxVerificationsSteps = ProtectedLogDevice.getMaxVerificationsSteps();
		ManualUpdateCache cache = ManualUpdateCache.getNewInstance("LogVerification");
		ProtectedLogEventRow currentProtectedLogEventRow = protectedLogEventRow;
		int verifiedSteps = -1;
		while (true) {
			if (checkVerifiedSteps && verifiedSteps == maxVerificationsSteps) {
				if (log.isTraceEnabled()) {
					log.trace("<verifyProtectedLogEventRow: 0");
				}
				return 0;
			}
			verifiedSteps++;
			// Is the current row available in cache
			if (cache.isPresent(currentProtectedLogEventRow)) {
				if (log.isDebugEnabled()) {
					log.debug("Cache hit at " +currentProtectedLogEventRow.getEventIdentifier().getCounter() + " " +
							currentProtectedLogEventRow.getEventIdentifier().getNodeGUID());
				}
				cache.updateCache();
				if (log.isTraceEnabled()) {
					log.trace("<verifyProtectedLogEventRow: 1");
				}
				return 1;
			}
			if (currentProtectedLogEventRow.getProtection() != null) {
				// If signed the search ends here and the chains is ok if the signature is ok
				IProtectedLogToken protectedLogToken = getToken(currentProtectedLogEventRow.getProtectionKeyIdentifier());
				try {
					if (protectedLogToken.verify(currentProtectedLogEventRow.getAsByteArray(false), currentProtectedLogEventRow.getProtection())) {
						cache.updateCache();
						if (log.isTraceEnabled()) {
							log.trace("<verifyProtectedLogEventRow: 1");
						}
						return 1;
					} else {
						if (log.isTraceEnabled()) {
							log.trace("<verifyProtectedLogEventRow: -1");
						}
						return -1;
					}
				} catch (Exception e) {
					if (log.isDebugEnabled()) {
						log.debug("Could not verify.", e);
					}
					if (log.isTraceEnabled()) {
						log.trace("<verifyProtectedLogEventRow: -1");
					}
					return -1;
				}
			} else {
				// Fetch next from this node
				ProtectedLogEventIdentifier nextProtectedLogEventIdentifier = new ProtectedLogEventIdentifier(
						currentProtectedLogEventRow.getEventIdentifier().getNodeGUID(), currentProtectedLogEventRow.getEventIdentifier().getCounter()+1);
				ProtectedLogEventRow nextProtectedLogEventRow = getProtectedLogEventRow(nextProtectedLogEventIdentifier);
				if (nextProtectedLogEventRow == null) {
					if (log.isTraceEnabled()) {
						log.trace("<verifyProtectedLogEventRow: -1");
					}
					return -1;
				}
				// Make sure that one links in all hashes properly
				ProtectedLogEventIdentifier[] linkedInEventIdentifiers = nextProtectedLogEventRow.getLinkedInEventIdentifiers();
				// Create a hash of the linked in nodes
				MessageDigest messageDigest = null;
				try {
					messageDigest = MessageDigest.getInstance(nextProtectedLogEventRow.getCurrentHashAlgorithm(), "BC");
				} catch (NoSuchAlgorithmException e) {
					throw new EJBException(e);
				} catch (NoSuchProviderException e) {
					throw new EJBException(e);
				}
				// Chain nodes with hash
				byte[] linkedInEventsHash = null;
				if (linkedInEventIdentifiers != null && linkedInEventIdentifiers.length != 0) {
					for (int i=0; i<linkedInEventIdentifiers.length; i++) {
						messageDigest.update(getProtectedLogEventRow(linkedInEventIdentifiers[i]).calculateHash());
					}
					linkedInEventsHash = messageDigest.digest();
				}
				// Make sure the hash at the next row is the same as the stored value (this means the current row are ok if the next one is)
				if (Arrays.equals(linkedInEventsHash, nextProtectedLogEventRow.getLinkedInEventsHash())) {
					// Recurse through the chain until a protected row is found.
					currentProtectedLogEventRow = nextProtectedLogEventRow;
				} else {
					if (log.isTraceEnabled()) {
						log.trace("<verifyProtectedLogEventRow: -1");
					}
					return -1;
				}
			}
			if (log.isTraceEnabled()) {
				log.trace("<verifyProtectedLogEventRow");
			}
		}
	}

	/**
	 * Verify entire log
	 * Verify that log hasn't been frozen for any node
	 * Verify that each protect operation had a valid certificate and is not about to expire without a valid replacement
	 * Verify that no nodes exists that haven't been processed
	 * 
	 * Starts at the specified event and traverses through the chain of linked in events, following one nodeGUID at
	 * the time. The newest signature for each node is verifed and the link-in hashes for each event. The
	 * verification continues node by node, until the oldest event is reached or the time where an verified exporting
	 * delete was last made.
	 * 
	 * @param freezeThreshold longest allowed time to newest ProtectedLogEvent of any node (milliseconds)
	 * @return null if log verification was ok, a ProtectedLogEventIdentifier for the row where verification failed if verification failed.
     *
	 * @ejb.interface-method view-type="both"
	 */
	public ProtectedLogEventIdentifier verifyEntireLog(int actionType, long freezeThreshold) {
		log.trace(">verifyEntireLog");
		ProtectedLogActions protectedLogActions = new ProtectedLogActions(actionType);
		ProtectedLogVerifier protectedLogVerifier = ProtectedLogVerifier.instance();
		ArrayList<ProtectedLogEventRow> newestProtectedLogEventRows = new ArrayList<ProtectedLogEventRow>();
		ArrayList<Integer> knownNodeGUIDs = new ArrayList<Integer>();
		ArrayList<Integer> processedNodeGUIDs = new ArrayList<Integer>();
		long stopTime = 0;
		// The time right after last chunk was exported (if it was deleted too)
		long lastDeletingExportTime = 0;
		ArrayList<ProtectedLogEventIdentifier> lastExportProtectedLogIdentifier = new ArrayList<ProtectedLogEventIdentifier>();
		ProtectedLogExportRow protectedLogExportRow = getLastSignedExport();
		if (protectedLogExportRow != null && protectedLogExportRow.getDeleted()) {
			if (!verifySignature(protectedLogExportRow.getAsByteArray(false), protectedLogExportRow.getSignature(),
					protectedLogExportRow.getSignatureCertificate(), protectedLogExportRow.getTimeOfExport())) {
				protectedLogActions.takeActions(IProtectedLogAction.CAUSE_INVALID_EXPORT);
				return null;
			}
			lastDeletingExportTime = protectedLogExportRow.getExportEndTime();
			// Fetch the identifier for this/these last event
			Collection<ProtectedLogData> protectedLogDatas = ProtectedLogData.findProtectedLogEventsByTime(entityManager, lastDeletingExportTime);
			Iterator<ProtectedLogData> i = protectedLogDatas.iterator();
			while (i.hasNext()) {
				ProtectedLogData protectedLogData = i.next();
				if (verifyProtectedLogEventRow(protectedLogData.toProtectedLogEventRow(), false) == 1) {
					lastExportProtectedLogIdentifier.add(new ProtectedLogEventIdentifier(protectedLogData.getNodeGUID(), protectedLogData.getCounter()));
				}
				if (protectedLogVerifier != null && protectedLogVerifier.isCanceled()) {
					log.info(intres.getLocalizedMessage("protectedlog.canceledver"));
					return null;
				}
			}
		}
		// Find newest protected LogEventRow.
		ProtectedLogEventIdentifier newestProtectedLogEventIdentifier = findNewestProtectedLogEventRow();
		if (newestProtectedLogEventIdentifier == null) {
        	log.error(intres.getLocalizedMessage("protectedlog.error.emptyorunprotected"));
			protectedLogActions.takeActions(IProtectedLogAction.CAUSE_EMPTY_LOG);
			return null;
		}
		knownNodeGUIDs.add(newestProtectedLogEventIdentifier.getNodeGUID());
		ProtectedLogEventRow tmpPLER = getProtectedLogEventRow(newestProtectedLogEventIdentifier);
		if (tmpPLER == null) {
			protectedLogActions.takeActions(IProtectedLogAction.CAUSE_MISSING_LOGROW);
			return newestProtectedLogEventIdentifier;
		}
		newestProtectedLogEventRows.add(tmpPLER);
		// Find the oldest LogEventRow and save this time as “stoptime”.
		ProtectedLogEventIdentifier oldestProtectedLogEventIdentifier = findOldestProtectedLogEventRow();
		stopTime = getProtectedLogEventRow(oldestProtectedLogEventIdentifier).getEventTime();

		// Keep track of all found nodes and their newest known LogEventRow. Also keep track of which nodes already has been verified.

		// While there still are unverified nodes left: verify the node-chain with the newest LogEventRow until “stoptime” or a the latest
		//  verified exportEndTime is reached. The later only applies if export is configured to remove the exported events.
		while (knownNodeGUIDs.size() > processedNodeGUIDs.size()) {
			// Pick newest know event of newestProtectedLogEventIdentifiers
			ProtectedLogEventRow nextProtectedLogEventRow = null;
			Iterator<ProtectedLogEventRow> iterator = newestProtectedLogEventRows.iterator();
			while (iterator.hasNext()) {
				if (protectedLogVerifier != null && protectedLogVerifier.isCanceled()) {
		        	log.info(intres.getLocalizedMessage("protectedlog.canceledver"));
					return null;
				}
				ProtectedLogEventRow i = iterator.next();
				int rowguid = i.getEventIdentifier().getNodeGUID();
				if ( !processedNodeGUIDs.contains(rowguid)
						&&  (nextProtectedLogEventRow == null || nextProtectedLogEventRow.getEventTime() < i.getEventTime()) ) {
					nextProtectedLogEventRow = i;
				}
			}
			int nextProtectedLogEventRowNodeGUID = nextProtectedLogEventRow.getEventIdentifier().getNodeGUID();
			processedNodeGUIDs.add(nextProtectedLogEventRowNodeGUID);
			// Verify that log hasn't been frozen for any node ( = ends with an stopevent or is newer than a certain time )
			ProtectedLogEventIdentifier newestNodeProtectedLogEventIdentifier = findNewestProtectedLogEventRow(nextProtectedLogEventRowNodeGUID);
			ProtectedLogEventRow newestNodeProtectedLogEventRow = getProtectedLogEventRow(newestNodeProtectedLogEventIdentifier);
			if (newestNodeProtectedLogEventRow == null) {
	        	log.error(intres.getLocalizedMessage("protectedlog.error.couldnotfetch",
	        			newestNodeProtectedLogEventIdentifier.getNodeGUID(), newestNodeProtectedLogEventIdentifier.getCounter()));
				protectedLogActions.takeActions(IProtectedLogAction.CAUSE_MISSING_LOGROW);
				return newestNodeProtectedLogEventIdentifier;
			}
			if (newestNodeProtectedLogEventRow.getEventId() != LogConstants.EVENT_SYSTEM_STOPPED_LOGGING 
					&& newestNodeProtectedLogEventRow.getEventTime() < new Date().getTime() - freezeThreshold ) {
	        	log.error(intres.getLocalizedMessage("protectedlog.error.frozen",
	        			newestNodeProtectedLogEventIdentifier.getNodeGUID()));
				protectedLogActions.takeActions(IProtectedLogAction.CAUSE_FROZEN);
				return newestNodeProtectedLogEventIdentifier;
			}

			// while not reached stoptime
			boolean isTopSignatureVerified = false;
			while (nextProtectedLogEventRow != null && nextProtectedLogEventRow.getEventTime() >= stopTime && nextProtectedLogEventRow.getEventTime() > lastDeletingExportTime) {
				if (protectedLogVerifier != null && protectedLogVerifier.isCanceled()) {
		        	log.info(intres.getLocalizedMessage("protectedlog.canceledver"));
					return null;
				}
				ProtectedLogEventIdentifier nextProtectedLogEventIdentifier = nextProtectedLogEventRow.getEventIdentifier();
				// Verify current signature if it is the newest one of this chain ( = if all hashes are correct up till this point the chain is ok, there is no need to every signature )
				if (!isTopSignatureVerified) {
					IProtectedLogToken currentToken = getToken(nextProtectedLogEventRow.getProtectionKeyIdentifier());
					if (currentToken == null) {
						protectedLogActions.takeActions(IProtectedLogAction.CAUSE_MISSING_TOKEN);
						return nextProtectedLogEventIdentifier;
					}
					isTopSignatureVerified = true;
					if (!currentToken.verify(nextProtectedLogEventRow.getAsByteArray(false), nextProtectedLogEventRow.getProtection())) {
						protectedLogActions.takeActions(IProtectedLogAction.CAUSE_MODIFIED_LOGROW);
						return nextProtectedLogEventIdentifier;
					}
					if (!verifyCertificate(currentToken.getTokenCertificate(), nextProtectedLogEventRow.getEventTime())) {
						protectedLogActions.takeActions(IProtectedLogAction.CAUSE_INVALID_TOKEN);
						return nextProtectedLogEventIdentifier;
					}
				}
				// Get linked in events
				ProtectedLogEventIdentifier[] linkedInEventIdentifiers = nextProtectedLogEventRow.getLinkedInEventIdentifiers();
				if (linkedInEventIdentifiers == null || linkedInEventIdentifiers.length == 0) {
					// It is valid for the first event of a chain, not to link in previous chains (e.g. the first event ever has no one to link to..)
					if (nextProtectedLogEventIdentifier.getCounter() != 0) {
						protectedLogActions.takeActions(IProtectedLogAction.CAUSE_INTERNAL_ERROR);
						return nextProtectedLogEventRow.getEventIdentifier();
					}
				}
				//  Verify hash for all events
				MessageDigest messageDigest = null;
				try {
					messageDigest = MessageDigest.getInstance(nextProtectedLogEventRow.getCurrentHashAlgorithm(), "BC");
				} catch (Exception e) {
					log.error("", e);
					throw new EJBException(e);
				}
				// Is the the current event nextProtectedLogEventRow the last non-delete-exported event?
				boolean isLastEvent = false;
				Iterator<ProtectedLogEventIdentifier> iterator3 = lastExportProtectedLogIdentifier.iterator();
				while (iterator3.hasNext()) {
					ProtectedLogEventIdentifier plei = iterator3.next();
					if (plei.equals(nextProtectedLogEventRow.getEventIdentifier())) {
						isLastEvent = true;
					}
				}
				byte[] linkedInEventsHash = null;
				ProtectedLogEventRow[] linkedInEventRows = null;
				if (!isLastEvent && linkedInEventIdentifiers != null && linkedInEventIdentifiers.length != 0) {
					linkedInEventRows = new ProtectedLogEventRow[linkedInEventIdentifiers.length];
					// If one of the linked in identifiers points to a ProtectedLogEventRow where eventTime is the same as
					// the latest Export and that export is "deleted" and has a valid signature, we can't verify it's linked in hash..
					// If not every log-row is signed in a multi-node environment, this would lead to unverified log-rows.
					boolean isLinkingInLast = false;
					for (int i=0; i<linkedInEventIdentifiers.length; i++) {
						if (lastExportProtectedLogIdentifier.contains(linkedInEventIdentifiers[i])) {
							isLinkingInLast = true;
							break;
						}
					}
					if (!isLinkingInLast) {
						// Verify the hash of all the linked in events.
						for (int i=0; i<linkedInEventIdentifiers.length; i++) {
							if (protectedLogVerifier != null && protectedLogVerifier.isCanceled()) {
					        	log.info(intres.getLocalizedMessage("protectedlog.canceledver"));
								return null;
							}
							linkedInEventRows[i] =getProtectedLogEventRow(linkedInEventIdentifiers[i]);
							if (linkedInEventRows[i] == null) {
								protectedLogActions.takeActions(IProtectedLogAction.CAUSE_MISSING_LOGROW);
								return linkedInEventIdentifiers[i];
							} else {
								messageDigest.update(linkedInEventRows[i].calculateHash());
							}
						}
						linkedInEventsHash = messageDigest.digest();
						if ((linkedInEventsHash != null || nextProtectedLogEventRow.getLinkedInEventsHash() != null) &&
								!Arrays.equals(linkedInEventsHash, nextProtectedLogEventRow.getLinkedInEventsHash())) {
							protectedLogActions.takeActions(IProtectedLogAction.CAUSE_MODIFIED_LOGROW); 
							return nextProtectedLogEventRow.getEventIdentifier();
						}
					}
				}
				nextProtectedLogEventRow = null;
				if (!isLastEvent && linkedInEventIdentifiers != null && linkedInEventIdentifiers.length != 0) {
					// For each linked in, if any of them is newer then the one found in newestProtectedLogEventIdentifiers for each node → verify event signature and replace
					for (int l=0; l<linkedInEventIdentifiers.length; l++) {
						if (protectedLogVerifier != null && protectedLogVerifier.isCanceled()) {
				        	log.info(intres.getLocalizedMessage("protectedlog.canceledver"));
							return null;
						}
						ProtectedLogEventIdentifier k = linkedInEventIdentifiers[l];
						ProtectedLogEventRow currentProtectedLogEventRow = linkedInEventRows[l]; //getProtectedLogEventRow(k);
						if (currentProtectedLogEventRow == null) {
							protectedLogActions.takeActions(IProtectedLogAction.CAUSE_MISSING_LOGROW);
							return currentProtectedLogEventRow.getEventIdentifier();	// TODO: This must be a bug! Can only be null.
						}
						ProtectedLogEventRow toRemove = null;
						boolean knownNodeGUID = false;
						Iterator<ProtectedLogEventRow> iterator2 = newestProtectedLogEventRows.iterator();
						while (iterator2.hasNext()) {
							if (protectedLogVerifier != null && protectedLogVerifier.isCanceled()) {
					        	log.info(intres.getLocalizedMessage("protectedlog.canceledver"));
								return null;
							}
							ProtectedLogEventRow j = iterator2.next();
							if (j.getEventIdentifier().getNodeGUID() == currentProtectedLogEventRow.getEventIdentifier().getNodeGUID()
									&& j.getEventTime() < currentProtectedLogEventRow.getEventTime()) {
								toRemove = j;
								break;
							}
							if (k.getNodeGUID() == j.getEventIdentifier().getNodeGUID()) {
								knownNodeGUID = true;
							}
						}
						//log.debug("Current linked in GUID " + i.getNodeGUID() + " and counter " + i.getCounter());
						if (!knownNodeGUID) {
							log.debug("Found previously unknown node linked in: " + k.getNodeGUID());
							IProtectedLogToken currentToken = getToken(currentProtectedLogEventRow.getProtectionKeyIdentifier());
							if (!currentToken.verify(currentProtectedLogEventRow.getAsByteArray(false), currentProtectedLogEventRow.getProtection())) {
								protectedLogActions.takeActions(IProtectedLogAction.CAUSE_MODIFIED_LOGROW);
								return currentProtectedLogEventRow.getEventIdentifier();
							}
							newestProtectedLogEventRows.add(currentProtectedLogEventRow);
							knownNodeGUIDs.add(k.getNodeGUID());
						} else if (toRemove != null) {
							IProtectedLogToken currentToken = getToken(currentProtectedLogEventRow.getProtectionKeyIdentifier());
							if (currentToken == null) {
								protectedLogActions.takeActions(IProtectedLogAction.CAUSE_MISSING_TOKEN);
								return currentProtectedLogEventRow.getEventIdentifier();
							}
							if (!currentToken.verify(currentProtectedLogEventRow.getAsByteArray(false), currentProtectedLogEventRow.getProtection())) {
								protectedLogActions.takeActions(IProtectedLogAction.CAUSE_MODIFIED_LOGROW);
								return currentProtectedLogEventRow.getEventIdentifier();
							}
							newestProtectedLogEventRows.remove(toRemove);
							newestProtectedLogEventRows.add(currentProtectedLogEventRow);
						}
						// Find next for this chain 
						if (nextProtectedLogEventRowNodeGUID == k.getNodeGUID()) {
							nextProtectedLogEventRow = currentProtectedLogEventRow;
						}
					}
				}
			}
		}
		//Verify that no nodes exists that hasn't been processed
		Integer[] everyExistingNodeGUID = getAllNodeGUIDs();
		if (log.isDebugEnabled()) {
			log.debug("There exists: "+everyExistingNodeGUID.length+" nodeGUIDs");
			log.debug("We have processed: "+processedNodeGUIDs.size()+" nodeGUIDs");
		}
		for (int i=0; i<everyExistingNodeGUID.length; i++) {
			if (log.isDebugEnabled()) {
				log.debug("verifying that we did not miss to process nodeGUID: "+everyExistingNodeGUID[i]);
			}
			if (protectedLogVerifier != null && protectedLogVerifier.isCanceled()) {
	        	log.info(intres.getLocalizedMessage("protectedlog.canceledver"));
				return null;
			}
			if (!processedNodeGUIDs.contains(everyExistingNodeGUID[i])) {
				ProtectedLogEventIdentifier id = findNewestLogEventRow(everyExistingNodeGUID[i]);
				ProtectedLogEventRow row = getProtectedLogEventRow(id);
				Date d = new Date(row.getEventTime());
	        	log.info(intres.getLocalizedMessage("protectedlog.error.notprocessednodeguid", everyExistingNodeGUID[i], row.getNodeIP(), id.getCounter(), d));
				protectedLogActions.takeActions(IProtectedLogAction.CAUSE_UNVERIFYABLE_CHAIN);
				return new ProtectedLogEventIdentifier(everyExistingNodeGUID[i], 0);
			}
		}
		log.trace("<verifyEntireLog");
		return null;
	}

	/**
	 * Fetches a known token from the database or creates a new one, depending on the configuration.
	 * @ejb.interface-method view-type="both"
	 * @ejb.transaction type="Required"
	 */
	@TransactionAttribute(TransactionAttributeType.REQUIRED)
	public IProtectedLogToken getProtectedLogToken() {
		log.trace(">getProtectedLogToken");
		IProtectedLogToken protectedLogToken = null;
		try {
			// Get ProtectedLogToken from configuration data
			final int protectionTokenReferenceType = ProtectedLogConfiguration.getProtectionTokenReferenceType();
			final String protectionTokenReference = ProtectedLogConfiguration.getTokenReference();
			final String protectionTokenKeyStoreAlias = ProtectedLogConfiguration.getKeyStoreAlias();
			final String protectionTokenKeyStorePassword = StringTools.passwordDecryption(ProtectedLogConfiguration.getKeyStorePassword(),ProtectedLogConfiguration.CONFIG_KEYSTOREPASSWORD);
			Certificate protectedLogTokenCertificate = null;
			if (protectionTokenReferenceType == ProtectedLogConfiguration.TOKENREFTYPE_CANAME) {
				// Use a CA as token
				CAInfo caInfo = caAdminSession.getCAInfo(internalAdmin, protectionTokenReference);
				if (caInfo == null) {
					// Revert to the "none" token.
		        	log.error(intres.getLocalizedMessage("protectedlog.error.reverttonone"));
					protectedLogToken = new ProtectedLogToken();
				} else {
					protectedLogTokenCertificate = (Certificate) caInfo.getCertificateChain().iterator().next();
					protectedLogToken = new ProtectedLogToken(caInfo.getCAId(), protectedLogTokenCertificate);
				}
			} else if (protectionTokenReferenceType == ProtectedLogConfiguration.TOKENREFTYPE_NONE) {
				// This is the default key used during startup. It can't sign or verify anything.
				protectedLogToken = new ProtectedLogToken();
			} else if (protectionTokenReferenceType == ProtectedLogConfiguration.TOKENREFTYPE_DATABASE) {
				// protectionTokenReference contains token id i database
				protectedLogToken = getToken(Integer.parseInt(protectionTokenReference, 10));
			} else {
				InputStream is = null;
				if (protectionTokenReferenceType == ProtectedLogConfiguration.TOKENREFTYPE_URI) {
					// Use a URI as token
					is = (new URI(protectionTokenReference)).toURL().openStream();
				} else if (protectionTokenReferenceType == ProtectedLogConfiguration.TOKENREFTYPE_CONFIG) {
					// protectionTokenReference contains b64encoded JKS
					is = new ByteArrayInputStream(Base64.decode(protectionTokenReference.getBytes()));
				}
				KeyStore keyStore = null;
				Key protectionKey = null;
				keyStore = KeyStore.getInstance("JKS");
				keyStore.load(is, protectionTokenKeyStorePassword.toCharArray());
				protectionKey = keyStore.getKey(protectionTokenKeyStoreAlias, protectionTokenKeyStorePassword.toCharArray());
				protectedLogTokenCertificate = keyStore.getCertificate(protectionTokenKeyStoreAlias);
				// Validate certificate here
				if (!verifyCertificate(protectedLogTokenCertificate, new Date().getTime())) {
		        	log.error(intres.getLocalizedMessage("protectedlog.error.invalidtokencert"));
					return null;
				}
				if (protectionKey instanceof PrivateKey) {
					protectedLogToken = new ProtectedLogToken((PrivateKey) protectionKey, protectedLogTokenCertificate);
				} else {
					// TODO: When implementing support for symmetric protection token:
					//  Verify custom extension of cert so we know the certificate belongs to this symmetric key
					protectedLogToken = new ProtectedLogToken((SecretKey) protectionKey, protectedLogTokenCertificate);
				}
			}
			// Check if token already exists and add it to the list of used tokens otherwise
			int tokenIdentifier = protectedLogToken.getIdentifier();
			if (getToken(tokenIdentifier) == null) {
				addToken(protectedLogToken);
			}
		} catch (Exception e) {
			log.error("", e);
		}
		log.trace("<getProtectedLogToken");
		return protectedLogToken;
	}

	/**
	 * Insert a new signed stop event for each unsigned node-chain in a "near future" and let the real node chain in these events..
	 * @param signAll is true if all unprotected chains should be signed, not just frozen ones
	 * 
	 * @ejb.interface-method view-type="both"
	 * @ejb.transaction type="RequiresNew"
	 */
	@TransactionAttribute(TransactionAttributeType.REQUIRES_NEW)
	public boolean signAllUnsignedChains(boolean signAll) {
		log.trace(">signAllUnsignedChains: "+signAll);
		// Find last unsigned event for all nodes, sorted by time, oldest first
		Integer[] nodeGUIDs = null;
		if (!signAll) {
			// Add protection to chains that have frozen
			Integer[] allNodeGUIDs = getNodeGUIDs(0, new Date().getTime());
			ArrayList<Integer> nodeGUIDsArray = new ArrayList<Integer>();
			long freezeTreshold = ProtectedLogDevice.getFreezeTreshold();
			for (int i=0; i<allNodeGUIDs.length; i++) {
				ProtectedLogEventRow protectedLogEventRow = getProtectedLogEventRow(findNewestLogEventRow(allNodeGUIDs[i]));
				if (protectedLogEventRow != null && protectedLogEventRow.getEventTime() < new Date().getTime() - freezeTreshold &&
						protectedLogEventRow.getEventId() != LogConstants.EVENT_SYSTEM_STOPPED_LOGGING) {
					if (log.isDebugEnabled()) {
						log.debug("Found a frozen node GUID: "+allNodeGUIDs[i]);
					}
					nodeGUIDsArray.add(allNodeGUIDs[i]);
				}
			}
			nodeGUIDs = (Integer[]) nodeGUIDsArray.toArray(new Integer[0]);
		} else {
			// Add protected to chains that have no previous protection
			nodeGUIDs = getFullyUnprotectedNodeGUIDs();
		}
		// Get latest real signed event
		ProtectedLogEventRow newestProtectedLogEventRow = getProtectedLogEventRow(findNewestProtectedLogEventRow());
		if (newestProtectedLogEventRow == null) {
			log.info("Could not find any signed log-events. Is there any? Is a token in use?");
			return false;
		}
		List<Integer> unsignedNodeGUIDs = Arrays.asList(nodeGUIDs);
		if (log.isDebugEnabled()) {
			if (unsignedNodeGUIDs.isEmpty()) {
				log.debug("No unsigned node GUIDs found.");
			}
		}
		Iterator<Integer> i = unsignedNodeGUIDs.iterator();
		while (i.hasNext()) {
			Integer nodeGUID = i.next();
			if (!signUnsignedChain( newestProtectedLogEventRow, nodeGUID)) {
				return false;
			}
		}
		log.trace("<signAllUnsignedChains");
		return true;
	}

	/**
	 * Create a new signed log event that links in unsigned log chain identified by nodeGUID
	 * @param nodeGUID the nodeGUID to accept and link in
	 * @return true if ok, false if MessageDigest cannot be created of any signed log events could not be found (if newestProtectedLogEventRow is null)
	 * 
	 * @ejb.interface-method view-type="both"
	 * @ejb.transaction type="Required"
	 */
	@TransactionAttribute(TransactionAttributeType.REQUIRED)
	public boolean signUnsignedChainUsingSingleSignerNode(Integer nodeGUID) {
		return signUnsignedChain(null, nodeGUID);
	}

	/**
	 * @param newestProtectedLogEventRow the latest real signed event or null if the method should try to find it itself
	 * @param nodeGUID the nodeGUID to accept and link in
	 * @return true if ok, false if MessageDigest can not be created of any signed log evens could not be found (if newestProtectedLogEventRow is null)
	 * 
	 * @ejb.interface-method view-type="both"
	 * @ejb.transaction type="Required"
	 */
	@TransactionAttribute(TransactionAttributeType.REQUIRED)
	public boolean signUnsignedChain(ProtectedLogEventRow newestProtectedLogEventRow, Integer nodeGUID) {
		if (log.isDebugEnabled()) {
			log.debug("Unsigned node GUID: "+nodeGUID);
		}
		if (newestProtectedLogEventRow == null) {
			newestProtectedLogEventRow = getProtectedLogEventRow(findNewestProtectedLogEventRow());
			if (newestProtectedLogEventRow == null) {
				log.info("Could not find any signed log-events. Is there any? Is a token in use?");
				return false;
			}
		}
		if (nodeGUID.intValue() == newestProtectedLogEventRow.getEventIdentifier().getNodeGUID()) {
			if (log.isDebugEnabled()) {
				log.debug("This unsigned node GUID is the same as this nodes GUID, skipping and continuing.");
			}
			return true;
		}
		// Find last event, signed or unsigned
		ProtectedLogEventIdentifier currentProtectedLogEventIdentifier = findNewestLogEventRow(nodeGUID);
		ProtectedLogEventRow currentProtectedLogEventRow = getProtectedLogEventRow(currentProtectedLogEventIdentifier);
		// Create a new event that links in this one
		ProtectedLogEventIdentifier[] linkedInEventIdentifiers = new ProtectedLogEventIdentifier[1];
		linkedInEventIdentifiers[0] = currentProtectedLogEventIdentifier;
		if (log.isDebugEnabled()) {
			log.debug("Linking in: "+currentProtectedLogEventIdentifier.getNodeGUID()+", "+currentProtectedLogEventIdentifier.getCounter());
		}
		MessageDigest messageDigest;
		try {
			messageDigest = MessageDigest.getInstance(newestProtectedLogEventRow.getCurrentHashAlgorithm(), "BC");
		} catch (Exception e) {
			log.error("MessageDigest.getInstance failed.", e);
			return false;
		}
		messageDigest.update(currentProtectedLogEventRow.calculateHash());
		byte[] linkedInEventsHash = messageDigest.digest();
		String nodeIP = ProtectedLogConfiguration.getNodeIp(TCPTool.getNodeIP());
		ProtectedLogEventRow newProtectedLogEventRow = new ProtectedLogEventRow(Admin.TYPE_INTERNALUSER, null, 0, LogConstants.MODULE_LOG,
				(new Date().getTime()+10000), null, null, null, LogConstants.EVENT_SYSTEM_STOPPED_LOGGING, "Node-chain was accepted by CLI.",
				new ProtectedLogEventIdentifier(currentProtectedLogEventIdentifier.getNodeGUID(), currentProtectedLogEventIdentifier.getCounter()+1),
				nodeIP, linkedInEventIdentifiers, linkedInEventsHash, newestProtectedLogEventRow.getCurrentHashAlgorithm(),
				newestProtectedLogEventRow.getProtectionKeyIdentifier(), newestProtectedLogEventRow.getProtectionKeyAlgorithm(), null);
		// Sign new event
		newProtectedLogEventRow.setProtection(getProtectedLogToken().protect(newProtectedLogEventRow.getAsByteArray(false)));
		// Persist event
		addProtectedLogEventRow(newProtectedLogEventRow);
		log.info(intres.getLocalizedMessage("protectedlog.acceptedchain", currentProtectedLogEventIdentifier.getNodeGUID()));
		return true;
	}

	/**
	 * Optionally exports and then deletes the entire log and export table.
	 * Writes an export to the database with the deleted events' times
	 * @ejb.interface-method view-type="both"
	 * @ejb.transaction type="RequiresNew"
	 */
	@TransactionAttribute(TransactionAttributeType.REQUIRES_NEW)
	public boolean resetEntireLog(boolean export) {
		log.trace(">resetEntireLog");
		// Start by disabling services
		if (!stopServices()) {
			return false;
		}
		try {
			IProtectedLogExportHandler protectedLogExportHandler = null;
			try {
				if (export) {
					Class implClass = Class.forName(ProtectedLogConfiguration.getExportHandlerClassName());
					protectedLogExportHandler = (IProtectedLogExportHandler) implClass.newInstance();
				} else {
					protectedLogExportHandler = new ProtectedLogDummyExportHandler();
				}
			} catch (Exception e1) {
				log.error("", e1);
				return false;
			}
			String currentHashAlgorithm = ProtectedLogConfiguration.getExportHashAlgorithm();
			// Nuke export table
			if (!removeAllExports(true)) {
				return false;
			}
			// Do an export but don't validate anything and do not perform any actions
			// TODO: This is ripped from export.. Try to merge some functionality into new method.
			ProtectedLogExportRow reservedProtectedLogExportRow = reserveExport(0);
			boolean success = false;
			boolean deleteAfterExport = true;
			ProtectedLogEventRow lastProtectedLogEventRow = getProtectedLogEventRow(findNewestProtectedLogEventRow());
			long exportEndTime = lastProtectedLogEventRow.getEventTime();
			long exportStartTime = 0;
			try {
				protectedLogExportHandler.init(exportEndTime, exportStartTime, true); 
				ProtectedLogExportRow protectedLogExportRow = getLastSignedExport();
				// Process all LogEventRows in the timespan chronologically, oldest first
				// By sorting for newest first caching would be easier, but that would result in exported files with newest event first
				int fetchSize = 1000;
				ProtectedLogEventRow[] protectedLogEventRows = new ProtectedLogEventRow[0];
				MessageDigest messageDigest = MessageDigest.getInstance(currentHashAlgorithm, "BC");
				ProtectedLogEventRow newesetExportedProtectedLogEventRow = null;
				long lastLoopTime = exportStartTime;
				do {
					protectedLogEventRows = findNextProtectedLogEventRows(lastLoopTime, exportEndTime, fetchSize);
					for (int i=0; i<protectedLogEventRows.length; i++) {
						// Extract data from LogEventRow and send to interface + digest
						messageDigest.digest(protectedLogEventRows[i].getLogDataAsByteArray());
						if (!protectedLogExportHandler.update(protectedLogEventRows[i].getAdminType(), protectedLogEventRows[i].getAdmindata(), protectedLogEventRows[i].getCaid(),
								protectedLogEventRows[i].getModule(), protectedLogEventRows[i].getEventTime(), protectedLogEventRows[i].getUsername(),
								protectedLogEventRows[i].getCertificateSerialNumber(), protectedLogEventRows[i].getCertificateIssuerDN(), protectedLogEventRows[i].getEventId(),
								protectedLogEventRows[i].getEventComment())) {
					    	log.error(intres.getLocalizedMessage("protectedlog.error.handlerupdate"));
							return false;
						}
						newesetExportedProtectedLogEventRow = protectedLogEventRows[i];
					}
					if (newesetExportedProtectedLogEventRow != null) {
						lastLoopTime = newesetExportedProtectedLogEventRow.getEventTime() + 1;
					}
				} while(protectedLogEventRows.length > 0);
				// Calculate hash
				byte[] exportedHash = messageDigest.digest();
				byte[] lastExportedHash = null;
				if (protectedLogExportRow != null) {
					lastExportedHash = protectedLogExportRow.getLogDataHash();
				}
				if (newesetExportedProtectedLogEventRow != null) {
					// Final processing
					long timeOfExport = new Date().getTime();
					// Get token-cert
					Certificate certificate = getToken(newesetExportedProtectedLogEventRow.getProtectionKeyIdentifier()).getTokenCertificate();
					// if not CA-cert get the issuers cert
					int caId = CertTools.getSubjectDN(certificate).hashCode();
					CAInfo caInfo = caAdminSession.getCAInfo(new Admin(Admin.TYPE_INTERNALUSER), caId);
					if (caInfo == null) {
						caId = CertTools.getIssuerDN(certificate).hashCode();
						caInfo = caAdminSession.getCAInfo(new Admin(Admin.TYPE_INTERNALUSER), caId);
						if (caInfo == null) {
					    	log.error(intres.getLocalizedMessage("protectedlog.error.noexportca"));
							protectedLogExportHandler.abort();
							return false;
						} else {
							certificate = (Certificate) caInfo.getCertificateChain().iterator().next();
						}
					}
					ProtectedLogExportRow newProtectedLogExportRow = new ProtectedLogExportRow(timeOfExport, exportEndTime, exportStartTime, exportedHash,
							lastExportedHash, currentHashAlgorithm, certificate, deleteAfterExport, null);
					byte[] signature = signSession.signData(newProtectedLogExportRow.getAsByteArray(false), caId, SecConst.CAKEYPURPOSE_CERTSIGN);
					newProtectedLogExportRow.setSignature(signature);
					// Send to export interface
					if (!protectedLogExportHandler.done(currentHashAlgorithm, exportedHash, lastExportedHash)) {
						// Something went wrong here
				    	log.error(intres.getLocalizedMessage("protectedlog.error.handlerdone"));
						return false;
					}
					// Write to database
					reservedProtectedLogExportRow = newProtectedLogExportRow;
					success = true;
				} else {
			    	log.debug(intres.getLocalizedMessage("protectedlog.nonewevents"));
				}
			} catch (CATokenOfflineException e) {
		    	log.error(intres.getLocalizedMessage("protectedlog.error.catokenoffline"));
				return false;
			} catch (Exception e) {
				log.error("", e);
				throw new EJBException(e);
			} finally {
				completeExport(reservedProtectedLogExportRow, success);
				if (success && deleteAfterExport) {
					// Nuke it
					Integer[] tokenIdentifiers = findTokenIndentifiersUsedOnlyUntil(exportEndTime);
					removeAllUntil(exportEndTime);
					removeTokens(tokenIdentifiers);
				}
			}
			log.trace("<resetEntireLog");
			return success;
		} finally {
			// Enable services again
			startServices();
		}
	}
	
	/**
	 * Temporary halts the verification and export services
	 * @return true if successful
	 * @ejb.interface-method view-type="both"
	 */
	public boolean stopServices() {
		// Disable services first.
		ServiceConfiguration serviceConfiguration = serviceSession.getService(internalAdmin, ProtectedLogExportWorker.DEFAULT_SERVICE_NAME);
		if (serviceConfiguration != null) {
			serviceConfiguration.setActive(false);
			serviceSession.changeService(internalAdmin, ProtectedLogExportWorker.DEFAULT_SERVICE_NAME, serviceConfiguration, true);
		}
		serviceConfiguration = serviceSession.getService(internalAdmin, ProtectedLogVerificationWorker.DEFAULT_SERVICE_NAME);
		if (serviceConfiguration != null) {
			serviceConfiguration.setActive(false);
			serviceSession.changeService(internalAdmin, ProtectedLogExportWorker.DEFAULT_SERVICE_NAME, serviceConfiguration, true);
		}
		// Wait for already running instances of the services to stop. Time-out after x minutes.
		ProtectedLogVerifier protectedLogVerifier = ProtectedLogVerifier.instance();
		ProtectedLogExporter protectedLogExporter = ProtectedLogExporter.instance();
		if (protectedLogVerifier != null) {
			protectedLogVerifier.cancelVerification();
		}
		if (protectedLogExporter != null) {
			protectedLogExporter.cancelExport();
		}
		long waitedTime = 0;
		int timeOut = 60;
    	log.info(intres.getLocalizedMessage("protectedlog.waitingforservice", timeOut));
		try {
			while ( ((protectedLogVerifier != null && protectedLogVerifier.isRunning()) || (protectedLogExporter != null && protectedLogExporter.isRunning())) && waitedTime < timeOut*1000) {
				Thread.sleep(1000);
				waitedTime += 1000;
			}
		} catch (InterruptedException e) {
			log.error("", e);
		}
		if ((protectedLogVerifier != null && protectedLogVerifier.isRunning()) || (protectedLogExporter != null && protectedLogExporter.isRunning())) {
			return false;
		}
		return true;
	}
	
	/**
	 * Restarts the verification and export services
	 * @ejb.interface-method view-type="both"
	 */
	public void startServices() {
		// Enable services again
		ServiceConfiguration serviceConfiguration = serviceSession.getService(internalAdmin, ProtectedLogExportWorker.DEFAULT_SERVICE_NAME);
		if (serviceConfiguration != null) {
			serviceConfiguration.setActive(true);
			serviceSession.changeService(internalAdmin, ProtectedLogExportWorker.DEFAULT_SERVICE_NAME, serviceConfiguration, true);
		}
		serviceConfiguration = serviceSession.getService(internalAdmin, ProtectedLogVerificationWorker.DEFAULT_SERVICE_NAME);
		if (serviceConfiguration != null) {
			serviceConfiguration.setActive(true);
			serviceSession.changeService(internalAdmin, ProtectedLogExportWorker.DEFAULT_SERVICE_NAME, serviceConfiguration, true);
		}
	}

	/**
	 * Exports the log the the given export handler and stores a signed hash linking each export to the last one.
	 * @ejb.interface-method view-type="both"
	 * @ejb.transaction type="NotSupported"
	 */
	@TransactionAttribute(TransactionAttributeType.NOT_SUPPORTED)
	public boolean exportLog(IProtectedLogExportHandler protectedLogExportHandler,
			int actionType, String currentHashAlgorithm, boolean deleteAfterExport, long atLeastThisOld) {
		log.trace(">exportLog");
		ProtectedLogActions protectedLogActions = new ProtectedLogActions(actionType);
		ProtectedLogExportRow reservedProtectedLogExportRow = reserveExport(atLeastThisOld);
		if (reservedProtectedLogExportRow == null) {
			return false;
		}
    	log.info(intres.getLocalizedMessage("protectedlog.startingexport"));
		long exportEndTime = reservedProtectedLogExportRow.getExportEndTime();
		long exportStartTime = reservedProtectedLogExportRow.getExportStartTime();
		ProtectedLogExporter protectedLogExporter = ProtectedLogExporter.instance();
		boolean success = false;
		try {
			protectedLogExportHandler.init(exportEndTime, exportStartTime, false); 
			ProtectedLogExportRow protectedLogExportRow = getLastSignedExport();
			// Process all LogEventRows in the timespan chronologically, oldest first
			// By sorting for newest first caching would be easier, but that would result in exported files with newest event first
			int fetchSize = 1000;
			long rowCount = 0;
			ProtectedLogEventRow[] protectedLogEventRows = new ProtectedLogEventRow[0];
			MessageDigest messageDigest = MessageDigest.getInstance(currentHashAlgorithm, "BC");
			ProtectedLogEventRow newesetExportedProtectedLogEventRow = null;
			long lastLoopTime = exportStartTime;
			CAInfo caInfo = null;
			do {
				protectedLogEventRows = findNextProtectedLogEventRows(lastLoopTime, exportEndTime, fetchSize);
				rowCount += protectedLogEventRows.length;
		    	log.info(intres.getLocalizedMessage("protectedlog.progress", protectedLogEventRows.length, rowCount));
				for (int i=0; i<protectedLogEventRows.length; i++) {
					if (protectedLogExporter != null && protectedLogExporter.isCanceled()) {
				    	log.info(intres.getLocalizedMessage("protectedlog.canceledexp"));
						protectedLogExportHandler.abort();
						return false;
					}
					// Verify current by verifying every step to the next protected log event row with valid protection (cache all steps if signature was valid)
					if (verifyProtectedLogEventRow(protectedLogEventRows[i], false) != 1) {
						ProtectedLogEventIdentifier plei = protectedLogEventRows[i].getEventIdentifier();
				    	log.error(intres.getLocalizedMessage("protectedlog.error.exportverify", plei.getNodeGUID(), plei.getCounter()));
						protectedLogActions.takeActions(IProtectedLogAction.CAUSE_MODIFIED_LOGROW);
						return false;
					}
					// Extract data from LogEventRow and send to interface + digest
					messageDigest.digest(protectedLogEventRows[i].getLogDataAsByteArray());
					if (!protectedLogExportHandler.update(protectedLogEventRows[i].getAdminType(), protectedLogEventRows[i].getAdmindata(), protectedLogEventRows[i].getCaid(),
							protectedLogEventRows[i].getModule(), protectedLogEventRows[i].getEventTime(), protectedLogEventRows[i].getUsername(),
							protectedLogEventRows[i].getCertificateSerialNumber(), protectedLogEventRows[i].getCertificateIssuerDN(), protectedLogEventRows[i].getEventId(),
							protectedLogEventRows[i].getEventComment())) {
				    	log.error(intres.getLocalizedMessage("protectedlog.error.handlerupdate"));
						protectedLogActions.takeActions(IProtectedLogAction.CAUSE_INTERNAL_ERROR);
						return false;
					}
					newesetExportedProtectedLogEventRow = protectedLogEventRows[i];
				}
				if (newesetExportedProtectedLogEventRow != null) {
					lastLoopTime = newesetExportedProtectedLogEventRow.getEventTime() + 1;
				}
			} while(protectedLogEventRows.length >= fetchSize);
			// Calculate hash
			byte[] exportedHash = messageDigest.digest();
			byte[] lastExportedHash = null;
			if (protectedLogExportRow != null) {
				lastExportedHash = protectedLogExportRow.getLogDataHash();
			}
			if (newesetExportedProtectedLogEventRow != null) {
				// Final processing
				long timeOfExport = new Date().getTime();
				// Get token-cert
				Certificate certificate = getToken(newesetExportedProtectedLogEventRow.getProtectionKeyIdentifier()).getTokenCertificate();
				// if not CA-cert get the issuers cert
				int caId = CertTools.getSubjectDN(certificate).hashCode();
				int issuingCAId = CertTools.getIssuerDN(certificate).hashCode();
				if (caInfo == null || (caInfo.getCAId() != caId && caInfo.getCAId() != issuingCAId)) {
					// Cache CAInfo locally
					caInfo = caAdminSession.getCAInfo(new Admin(Admin.TYPE_INTERNALUSER), caId);	
					if (caInfo == null) {
						caId = issuingCAId;
						caInfo = caAdminSession.getCAInfo(new Admin(Admin.TYPE_INTERNALUSER), caId);
						if (caInfo == null) {
					    	log.error(intres.getLocalizedMessage("protectedlog.error.noexportcacert"));
							protectedLogActions.takeActions(IProtectedLogAction.CAUSE_INVALID_TOKEN);
							protectedLogExportHandler.abort();
							return false;
						} else {
							certificate = (Certificate) caInfo.getCertificateChain().iterator().next();
						}
					}
				}
				ProtectedLogExportRow newProtectedLogExportRow = new ProtectedLogExportRow(timeOfExport, exportEndTime, exportStartTime, exportedHash,
						lastExportedHash, currentHashAlgorithm, certificate, deleteAfterExport, null);
				byte[] signature = signSession.signData(newProtectedLogExportRow.getAsByteArray(false), caId, SecConst.CAKEYPURPOSE_CERTSIGN);
				newProtectedLogExportRow.setSignature(signature);
				// Send to interface
				if (!protectedLogExportHandler.done(currentHashAlgorithm, exportedHash, lastExportedHash)) {
					// Something went wrong here
			    	log.error(intres.getLocalizedMessage("protectedlog.error.handlerdone"));
					protectedLogActions.takeActions(IProtectedLogAction.CAUSE_INTERNAL_ERROR);
					return false;
				}
				// Write to database
				reservedProtectedLogExportRow = newProtectedLogExportRow;
				success = true;
			} else {
		    	log.debug(intres.getLocalizedMessage("protectedlog.nonewevents"));
			}
		} catch (CATokenOfflineException e) {
	    	log.error(intres.getLocalizedMessage("protectedlog.error.catokenoffline"));
			protectedLogActions.takeActions(IProtectedLogAction.CAUSE_INTERNAL_ERROR);
			return false;
		} catch (Exception e) {
			log.error("", e);
			throw new EJBException(e);
		} finally {
			completeExport(reservedProtectedLogExportRow, success);
			if (success && deleteAfterExport) {
				// Nuke it
				Integer[] tokenIdentifiers = findTokenIndentifiersUsedOnlyUntil(exportEndTime);
				removeAllUntil(exportEndTime);
				removeTokens(tokenIdentifiers);
			}
		}
		log.trace("<exportLog");
		return true;
	}
	
	/**
	 * @return true if one or more event with the specified time exists in the log
	 * 
	 * @ejb.interface-method view-type="both"
	 */
	public boolean existsAnyProtectedLogEventByTime(long time) {
		return !ProtectedLogData.findProtectedLogEventsByTime(entityManager, time).isEmpty();
	}
}
