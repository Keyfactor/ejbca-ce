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

import javax.crypto.Mac;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import javax.ejb.EJBException;
import javax.ejb.FinderException;
import javax.ejb.ObjectNotFoundException;

import org.apache.commons.lang.StringUtils;
import org.bouncycastle.util.encoders.Hex;
import org.ejbca.core.ejb.BaseSessionBean;
import org.ejbca.core.model.log.Admin;
import org.ejbca.core.model.protect.Protectable;
import org.ejbca.core.model.protect.TableVerifyResult;
import org.ejbca.util.CertTools;
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
 * @ejb.env-entry description="Enable or disable protection alltogether"
 *   name="enabled"
 *   type="java.lang.String"
 *   value="${protection.enabled}"
 *   
 * @ejb.env-entry description="Key (reference or actual key, depending on type) for protection"
 *   name="keyRef"
 *   type="java.lang.String"
 *   value="${protection.keyref}"
 *   
 * @ejb.env-entry description="Key for reference above"
 *   name="${protection.keyref}"
 *   type="java.lang.String"
 *   value="${protection.key}"
 *   
 * @ejb.env-entry description="Key type, HMAC or ENCHMAC"
 *   name="keyType"
 *   type="java.lang.String"
 *   value="${protection.keytype}"
 *   
 * @ejb.ejb-external-ref
 *   description="The Protect Entry Data entity bean"
 *   view-type="local"
 *   ejb-name="TableProtectDataLocal"
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
 * @version $Id: TableProtectSessionBean.java,v 1.1 2006-08-05 09:59:37 anatom Exp $
 */
public class TableProtectSessionBean extends BaseSessionBean {

	private static final String HMAC_ALG = "HMac-SHA256";
	
    /** The home interface of  LogEntryData entity bean */
    private TableProtectDataLocalHome protectentryhome;

    private String keyType;
    private String keyRef;
    private String key;
    boolean enabled = false;
    
    /**
     * Default create for SessionBean without any creation Arguments.
     */
    public void ejbCreate() {
        try {
        	CertTools.installBCProvider();
            protectentryhome = (TableProtectDataLocalHome) getLocator().getLocalHome(TableProtectDataLocalHome.COMP_NAME);
            keyType = getLocator().getString("java:comp/env/keyType");
            keyRef = getLocator().getString("java:comp/env/keyRef");
            String tmpkey = getLocator().getString("java:comp/env/"+keyRef);
            if (StringUtils.equalsIgnoreCase(keyType, "ENCHMAC")) {
            	key = StringTools.pbeDecryptStringWithSha256Aes192(tmpkey);
            } else {
            	key = tmpkey;
            }
            String en = getLocator().getString("java:comp/env/enabled");
            if (StringUtils.equalsIgnoreCase(en, "true")) {
            	enabled = true;
            }
        } catch (Exception e) {
            throw new EJBException(e);
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
    public void protect(Admin admin, Protectable entry) {
    	if (!enabled) {
    		return;
    	}
    	int hashVersion = entry.getHashVersion();
    	String dbKey = entry.getDbKeyString();
    	String dbType = entry.getEntryType();
		try {
			TableProtectDataLocal data = protectentryhome.findByDbTypeAndKey(dbType, dbKey);
			if (data != null) {
				error("PROTECT ERROR: protection row for entry type: "+dbType+", with key: "+dbKey+" already exists!");				
			}
		} catch (FinderException e1) {
	    	try {
	        	String hash = entry.getHash();
	    		String signature = createHmac(key, HMAC_ALG, hash);
	    		String id = GUIDGenerator.generateGUID(this);
	    		protectentryhome.create(id, hashVersion, HMAC_ALG, hash, signature, new Date(), dbKey, dbType, keyRef, keyType);
			} catch (Exception e) {
				error("PROTECT ERROR: can not create protection row for entry type: "+dbType+", with key: "+dbKey, e);
			}
		}
    } // protect

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
    public TableVerifyResult verify(Protectable entry) {
    	TableVerifyResult ret = new TableVerifyResult();
    	if (!enabled) {
    		return ret;
    	}
    	String dbKey = entry.getDbKeyString();
    	String dbType = entry.getEntryType();
    	try {
    		TableProtectDataLocal data = protectentryhome.findByDbTypeAndKey(dbType, dbKey);
    		int hashVersion = data.getHashVersion();
    		String hash = entry.getHash(hashVersion);
    		if (!StringUtils.equals(keyRef, data.getKeyRef())) {
    			ret.setResultCode(TableVerifyResult.VERIFY_NO_KEY);    			
    		} else {
        		// Create a new signature on the passed in object, and compare it with the one we have stored in the db'
    			if (log.isDebugEnabled()) {
        			log.debug("Hash is: "+hash);    				
    			}
        		String signature = createHmac(key, HMAC_ALG, hash);
    			if (log.isDebugEnabled()) {
        			log.debug("Signature is: "+signature);    				
    			}
        		if (!StringUtils.equals(signature, data.getSignature())) {
        			ret.setResultCode(TableVerifyResult.VERIFY_FAILED);
        		} else {
        			// This can actually never happen
            		if (!StringUtils.equals(hash, data.getHash())) {
            			ret.setResultCode(TableVerifyResult.VERIFY_WRONG_HASH);
            		}    			
        		}    			
    		}
		} catch (ObjectNotFoundException e) {
			info("PROTECT ERROR: can not find protection row for entry type: "+dbType+", with key: "+dbKey);
			ret.setResultCode(TableVerifyResult.VERIFY_NO_ROW);
		}catch (Exception e) {
			error("PROTECT ERROR: can not verify protection row for entry type: "+dbType+", with key: "+dbKey, e);
		}
		return ret;
    } // verify

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
    
} // TableProtectSessionBean
