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

package org.ejbca.core.ejb.protect;

import java.io.UnsupportedEncodingException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.util.Date;

import javax.annotation.PostConstruct;
import javax.crypto.Mac;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import javax.ejb.EJBException;
import javax.ejb.Stateless;
import javax.ejb.TransactionAttribute;
import javax.ejb.TransactionAttributeType;
import javax.persistence.EntityManager;
import javax.persistence.PersistenceContext;

import org.apache.commons.lang.StringUtils;
import org.apache.log4j.Logger;
import org.bouncycastle.util.encoders.Hex;
import org.ejbca.config.ProtectConfiguration;
import org.ejbca.core.model.InternalResources;
import org.ejbca.core.model.protect.Protectable;
import org.ejbca.core.model.protect.TableVerifyResult;
import org.ejbca.util.CryptoProviderTools;
import org.ejbca.util.GUIDGenerator;
import org.ejbca.util.StringTools;

/** For some setups there are requirements for integrity protection of 
 * database rows. 
 *
 * @ejb.bean
 *   display-name="TableProtectSB"
 *   name="TableProtectSession"
 *   jndi-name="TableProtectSession"
 *   local-jndi-name="TableProtectSessionLocal"
 *   view-type="both"
 *   type="Stateless"
 *   transaction-type="Container"
 *
 * @weblogic.enable-call-by-reference True
 *
 * @ejb.ejb-external-ref
 *   description="The Protect Entry Data entity bean"
 *   view-type="local"
 *   ref-name="ejb/TableProtectDataLocal"
 *   type="Entity"
 *   home="org.ejbca.core.ejb.protect.TableProtectDataLocalHome"
 *   business="org.ejbca.core.ejb.protect.TableProtectDataLocal"
 *   link="TableProtectData"
 *
 * @ejb.home
 *   extends="javax.ejb.EJBHome"
 *   local-extends="javax.ejb.EJBLocalHome"
 *   local-class="org.ejbca.core.ejb.protect.TableProtectSessionLocalHome"
 *   remote-class="org.ejbca.core.ejb.protect.TableProtectSessionHome"
 *
 * @ejb.interface
 *   extends="javax.ejb.EJBObject"
 *   local-extends="javax.ejb.EJBLocalObject"
 *   local-class="org.ejbca.core.ejb.protect.TableProtectSessionLocal"
 *   remote-class="org.ejbca.core.ejb.protect.TableProtectSessionRemote"
 *
 * @version $Id$
 */
@Stateless(mappedName = org.ejbca.core.ejb.JndiHelper.APP_JNDI_PREFIX + "TableProtectSessionRemote")
@TransactionAttribute(TransactionAttributeType.REQUIRED)
public class TableProtectSessionBean implements TableProtectSessionLocal, TableProtectSessionRemote {

	private static final Logger log = Logger.getLogger(TableProtectSessionBean.class);
    /** Internal localization of logs and errors */
    private static final InternalResources intres = InternalResources.getInstance();

    private static final String HMAC_ALG = "HMac-SHA256";
	
    @PersistenceContext(unitName="ejbca")
    private EntityManager entityManager;

    private String keyType = ProtectConfiguration.getProtectionKeyType();
    private String key = null;
    boolean warnOnMissingRow = ProtectConfiguration.getWarnOnMissingRow();
    
    /**
     * Default create for SessionBean without any creation Arguments.
     */
    @PostConstruct
    public void ejbCreate() {
        try {
        	CryptoProviderTools.installBCProvider();
            if (keyType == ProtectConfiguration.PROTECTIONTYPE_ENC_SOFT_HMAC) {
            	key = StringTools.pbeDecryptStringWithSha256Aes192(ProtectConfiguration.getProtectionKey());
            } else {
            	key = ProtectConfiguration.getProtectionKey();
            }
        } catch (Exception e) {
            throw new EJBException(e);
        }
    }

    /**
     * Store a protection entry in an external, remote database.
     *
     * @param Protectable the object beeing protected
     *
     * @ejb.interface-method
     * @ejb.transaction type="Required"
     */
    public void protectExternal(Protectable entry, String dataSource) {
    	if (!ProtectConfiguration.getProtectionEnabled()) {
    		return;
    	}
    	int hashVersion = entry.getHashVersion();
    	String dbKey = entry.getDbKeyString();
    	String dbType = entry.getEntryType();
		log.debug("Protecting entry, type: "+dbType+", with key: "+dbKey);
    	//String hash;
    	try {
    		String hash = entry.getHash();
    		String signature = createHmac(key, HMAC_ALG, hash);
    		TableProtectData tableProtectData = TableProtectData.findByDbTypeAndKey(entityManager, dbType, dbKey);
    		if (tableProtectData != null) {
				log.info(intres.getLocalizedMessage("protect.rowexistsupdate", dbType, dbKey));
    			tableProtectData.setDbKey(dbKey);
    			tableProtectData.setDbType(dbType);
    			tableProtectData.setHash(hash);
    			tableProtectData.setHashVersion(hashVersion);
    			tableProtectData.setKeyType(keyType);
    			tableProtectData.setProtectionAlg(HMAC_ALG);
    			tableProtectData.setSignature(signature);
    			tableProtectData.setTime(new Date().getTime());
    			tableProtectData.setVersion(TableProtectData.CURRENT_VERSION);
    		} else {
    			tableProtectData = new TableProtectData(GUIDGenerator.generateGUID(this), hashVersion, HMAC_ALG, hash, signature, new Date(), dbKey, dbType, keyType);
    			entityManager.persist(tableProtectData);
    		}
    		/*
    		String id = null;
    		try {
    			SelectProtectPreparer prep = new SelectProtectPreparer(dbType, dbKey);
        		id = JDBCUtil.executeSelectString("SELECT id FROM TableProtectData where dbType=? and dbKey=?",
        				prep, dataSource );    			
    		} catch (Exception e) {
    			
    		}
    		if (id != null) {
                String msg = intres.getLocalizedMessage("protect.rowexistsupdate", dbType, dbKey);            	
				log.info(msg);
				ProtectPreparer uprep = new ProtectPreparer(id, TableProtectData.CURRENT_VERSION, hashVersion, HMAC_ALG, hash, signature, (new Date()).getTime(), dbKey, dbType, keyType);
    			try {
    				JDBCUtil.execute( "UPDATE TableProtectData SET version=?,hashVersion=?,protectionAlg=?,hash=?,signature=?,time=?,dbKey=?,dbType=?,keyType=? WHERE id=?",
    						uprep, dataSource );
    			} catch (Exception ue) {
    				log.error("PROTECT ERROR: can not create protection row for entry type: "+dbType+", with key: "+dbKey, ue);
    			}
			} else {
	    		id = GUIDGenerator.generateGUID(this);
	        	try {
	        		ProtectPreparer prep = new ProtectPreparer(id, TableProtectData.CURRENT_VERSION, hashVersion, HMAC_ALG, hash, signature, (new Date()).getTime(), dbKey, dbType, keyType);
	        		JDBCUtil.execute( "INSERT INTO TableProtectData (version,hashVersion,protectionAlg,hash,signature,time,dbKey,dbType,keyType,id) VALUES (?,?,?,?,?,?,?,?,?,?)",
	        				prep, dataSource );
	        	} catch (Exception e) {
	                String msg = intres.getLocalizedMessage("protect.errorcreate", dbType, dbKey);            	
					log.error(msg, e);
	        	}
			} */
    	} catch (Exception e) {
            String msg = intres.getLocalizedMessage("protect.errorcreate", dbType, dbKey);            	
    		log.error(msg, e);
    	}
    }
    
    /**
     * Store a protection entry.
     *
     * @param admin the administrator performing the event.
     * @param Protectable the object beeing protected
     *
     * @ejb.interface-method
     * @ejb.transaction type="Required"
     */
    @TransactionAttribute(TransactionAttributeType.REQUIRED)
    public void protect(Protectable entry) {
    	if (!ProtectConfiguration.getProtectionEnabled()) {
        	if (log.isDebugEnabled()) {
            	log.debug("protect: not enabled");    		
        	}
    		return;
    	}
    	int hashVersion = entry.getHashVersion();
    	String dbKey = entry.getDbKeyString();
    	String dbType = entry.getEntryType();
		log.debug("Protecting entry, type: "+dbType+", with key: "+dbKey);
    	String hash;
    	try {
    		hash = entry.getHash();
    		String signature = createHmac(key, HMAC_ALG, hash);
    		String id = GUIDGenerator.generateGUID(this);
			TableProtectData data = TableProtectData.findByDbTypeAndKey(entityManager, dbType, dbKey);
			if (data != null) {
				String msg = intres.getLocalizedMessage("protect.rowexistsupdate", dbType, dbKey);            	
				log.info(msg);
				data.setHashVersion(hashVersion);
				data.setHash(hash);
				data.setProtectionAlg(HMAC_ALG);
				data.setSignature(signature);
				data.setTime((new Date()).getTime());
				data.setDbKey(dbKey);
				data.setDbType(dbType);
				data.setKeyType(keyType);
			} else {
				try {
					entityManager.persist(new TableProtectData(id, hashVersion, HMAC_ALG, hash, signature, new Date(), dbKey, dbType, keyType));
				} catch (Exception e) {
					String msg = intres.getLocalizedMessage("protect.errorcreate", dbType, dbKey);            	
					log.error(msg, e);
				}
    		}
    	} catch (Exception e) {
            String msg = intres.getLocalizedMessage("protect.errorcreate", dbType, dbKey);            	
    		log.error(msg, e);
    	}
    }

    /**
     * Verifies a protection entry.
     *
     * @param admin the administrator performing the event.
     * @param Protectable the object beeing verified
     * @return TableVerifyResult, never null
     * 
     * @ejb.interface-method
     * @ejb.transaction type="Supports"
     */
    @TransactionAttribute(TransactionAttributeType.SUPPORTS)
    public TableVerifyResult verify(Protectable entry) {
    	TableVerifyResult ret = new TableVerifyResult();
    	if (!ProtectConfiguration.getProtectionEnabled()) {
    		return ret;
    	}
    	String alg = HMAC_ALG;
    	String dbKey = entry.getDbKeyString();
    	String dbType = entry.getEntryType();
		log.debug("Verifying entry, type: "+dbType+", with key: "+dbKey);
    	try {
    		TableProtectData data = TableProtectData.findByDbTypeAndKey(entityManager, dbType, dbKey);
    		if (data != null) {
    			int hashVersion = data.getHashVersion();
    			String hash = entry.getHash(hashVersion);
    			if (!StringUtils.equals(alg, data.getProtectionAlg())) {
    				ret.setResultCode(TableVerifyResult.VERIFY_INCOMPATIBLE_ALG);    			
    				String msg = intres.getLocalizedMessage("protect.errorverifyalg", dbType, dbKey);            	
    				log.error(msg);
    			} else {
    				// Create a new signature on the passed in object, and compare it with the one we have stored in the db'
    				if (log.isDebugEnabled()) {
    					log.debug("Hash is: "+hash);    				
    				}
    				String signature = createHmac(key, alg, hash);
    				if (log.isDebugEnabled()) {
    					log.debug("Signature is: "+signature);    				
    				}
    				if (!StringUtils.equals(signature, data.getSignature())) {
    					ret.setResultCode(TableVerifyResult.VERIFY_FAILED);
    					String msg = intres.getLocalizedMessage("protect.errorverify", dbType, dbKey);            	
    					log.error(msg);
    				} else {
    					// This can actually never happen
    					if (!StringUtils.equals(hash, data.getHash())) {
    						ret.setResultCode(TableVerifyResult.VERIFY_WRONG_HASH);
    						String msg = intres.getLocalizedMessage("protect.errorverifywronghash", dbType, dbKey);            	
    						log.error(msg);
    					}    			
    				}    			
    			}
    		} else {
    			if (warnOnMissingRow) {
    				String msg = intres.getLocalizedMessage("protect.errorverifynorow", dbType, dbKey);            	
    				log.error(msg);				
    			}
    			ret.setResultCode(TableVerifyResult.VERIFY_NO_ROW);
    		}
		}catch (Exception e) {
            String msg = intres.getLocalizedMessage("protect.errorverifycant", dbType, dbKey);            	
			log.error(msg, e);
		}
		return ret;
    }

    private String createHmac(String pwd, String alg, String data) throws NoSuchAlgorithmException, NoSuchProviderException, UnsupportedEncodingException, InvalidKeyException {
        Mac mac = Mac.getInstance(alg, "BC");
        SecretKey key = new SecretKeySpec(pwd.getBytes("UTF-8"), alg);
        mac.init(key);
        mac.reset();
        byte[] dataBytes = data.getBytes("UTF-8");  
        mac.update(dataBytes, 0, dataBytes.length);
        byte[] out = mac.doFinal();
    	return new String(Hex.encode(out));
    }

    /*protected class SelectProtectPreparer implements JDBCUtil.Preparer {
    	private final String dbType;
    	private final String dbKey;
		public SelectProtectPreparer(final String dbType, final String dbKey) {
			super();
			this.dbType = dbType;
			this.dbKey = dbKey;
		}
		public void prepare(PreparedStatement ps) throws Exception {
            ps.setString(1, dbType);
            ps.setString(2, dbKey);
		}
        public String getInfoString() {
        	return "Select:, dbKey:"+dbKey+", dbType: "+dbType;
        }
    }

    protected class ProtectPreparer implements JDBCUtil.Preparer {
        private final String id;
        private final int version;
        private final int hashVersion;
        private final String alg;
        private final String hash;
        private final String signature;
        private final long time;
        private final String dbKey; 
        private final String dbType; 
        private final String keyType; 
        
        public ProtectPreparer(final String id, final int version, final int hashVersion, final String alg, final String hash, final String signature, final long time, final String dbKey, final String dbType, final String keyType) {
			super();
			this.id = id;
			this.version = version;
			this.hashVersion = hashVersion;
			this.alg = alg;
			this.hash = hash;
			this.signature = signature;
			this.time = time;
			this.dbKey = dbKey;
			this.dbType = dbType;
			this.keyType = keyType;
		}
		public void prepare(PreparedStatement ps) throws Exception {
            ps.setInt(1, version);
            ps.setInt(2, hashVersion);
            ps.setString(3, alg);
            ps.setString(4, hash);
            ps.setString(5, signature);
            ps.setLong(6, time);
            ps.setString(7, dbKey);
            ps.setString(8, dbType);
            ps.setString(9, keyType);
            ps.setString(10,id);
        }
        public String getInfoString() {
        	return "Store:, id: "+id+", dbKey:"+dbKey+", dbType: "+dbType;
        }
    }*/
}
