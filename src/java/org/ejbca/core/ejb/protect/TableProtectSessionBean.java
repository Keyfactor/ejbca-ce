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
}
