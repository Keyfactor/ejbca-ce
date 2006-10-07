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


import java.util.Date;

import javax.ejb.CreateException;

import org.ejbca.core.ejb.BaseEntityBean;

/** Entity bean should not be used directly, use though Session beans.
 *
 * Entity Bean representing a table protection entry in the log database.
 * Information stored:
 * <pre>
 *  id (Primary Key)
 *  version versioning of the protection rows (this row), so that the underlying database table can be upgraded and still verified.
 *  protectAlg hmac, rsaWithSHA1 etc. Also used to implicitly define the key type of the protection key.
 *  hashVersion versioning of the protected row, so the underlying database table can be extended and still verified
 *  hash hash of the row data from the underlying table to be protected.
 *  signature actual signature.
 *  dbKey database key of the underlying row that is protected, used to find the row for verification.
 *  dbType type of object protected, determined by the OBJECT, for example LOGENTRY
 *  keyRef reference to key used for protection.
 *  keyType type of key which the reference refers to
 * </pre>
 *
 * @ejb.bean
 *   description="This enterprise bean entity represents a Table Protection entry with accompanying data"
 *   display-name="TableProtectDataEB"
 *   name="TableProtectData"
 *   view-type="local"
 *   type="CMP"
 *   reentrant="False"
 *   cmp-version="2.x"
 *   transaction-type="Container"
 *   schema="TableProtectDataBean"
 *   primkey-field="id"
 *
 * @ejb.pk
 *   generate="false"
 *   class="java.lang.String"
 *
 * @ejb.persistence table-name = "TableProtectData"
 * 
 * @ejb.home
 *   generate="local"
 *   local-extends="javax.ejb.EJBLocalHome"
 *   local-class="org.ejbca.core.ejb.protect.TableProtectDataLocalHome"
 *
 * @ejb.interface
 *   generate="local"
 *   local-extends="javax.ejb.EJBLocalObject"
 *   local-class="org.ejbca.core.ejb.protect.TableProtectDataLocal"
 *
 * @ejb.transaction type="Required"
 *
 * @ejb.finder description="findByDbTypeAndKey"
 * signature="org.ejbca.core.ejb.protect.TableProtectDataLocal findByDbTypeAndKey(java.lang.String dbType, java.lang.String dbKey)"
 * query="SELECT OBJECT(a) from TableProtectDataBean a WHERE a.dbType=?1 AND a.dbKey=?2"
 *

 * @version $Id: TableProtectDataBean.java,v 1.4 2006-10-07 14:11:03 anatom Exp $
 */
public abstract class TableProtectDataBean extends BaseEntityBean {

	public static final String KEYTYPE_HMAC = "HMAC";
	
	public static final int CURRENT_VERSION = 1;
	
    /**
     * @ejb.pk-field
     * @ejb.persistence column-name="id"
     * @ejb.interface-method view-type="local"
     */
    public abstract String getId();

    /**
     */
    public abstract void setId(String id);

    /**
     * @ejb.persistence column-name="version"
     * @ejb.interface-method view-type="local"
     */
    public abstract int getVersion();

    /**
     * @ejb.interface-method view-type="local"
     */
    public abstract void setVersion(int version);

    /**
     * @ejb.persistence column-name="hashVersion"
     * @ejb.interface-method view-type="local"
     */
    public abstract int getHashVersion();

    /**
     * @ejb.interface-method view-type="local"
     */
    public abstract void setHashVersion(int version);
    
    /**
     * @ejb.persistence column-name="protectionAlg"
     * @ejb.interface-method view-type="local"
     */
    public abstract String getProtectionAlg();

    /**
     * @ejb.interface-method view-type="local"
     */
    public abstract void setProtectionAlg(String alg);

    /** 
     * @ejb.persistence column-name="hash"
     * @ejb.interface-method view-type="local"
     */
    public abstract String getHash();

    /**
     * @ejb.interface-method view-type="local"
     */
    public abstract void setHash(String hash);

    /** 
     * @ejb.persistence column-name="signature"
     * @ejb.interface-method view-type="local"
     */
    public abstract String getSignature();

    /**
     * @ejb.interface-method view-type="local"
     */
    public abstract void setSignature(String signature);

    /**
     * @ejb.persistence column-name="time"
     */
    public abstract long getTime();

    /**
     * @ejb.interface-method view-type="local"
     */
    public abstract void setTime(long time);

    /**
     * @ejb.persistence column-name="dbKey"
     * @ejb.interface-method view-type="local"
     */
    public abstract String getDbKey();

    /** 
     * @ejb.interface-method view-type="local"
     */
    public abstract void setDbKey(String dbKey);

    /**
     * @ejb.persistence column-name="dbType"
     * @ejb.interface-method view-type="local"
     */
    public abstract String getDbType();

    /** 
     * @ejb.interface-method view-type="local"
     */
    public abstract void setDbType(String dbType);

    /**
     * @ejb.persistence column-name="keyRef"
     * @ejb.interface-method view-type="local"
     */
    public abstract String getKeyRef();

    /**
     * @ejb.interface-method view-type="local"
     */
    public abstract void setKeyRef(String keyRef);

    /**
     * @ejb.persistence column-name="keyType"
     * @ejb.interface-method view-type="local"
     */
    public abstract String getKeyType();

    /**
     * @ejb.interface-method view-type="local"
     */
    public abstract void setKeyType(String keyType);

    /**
     * @ejb.interface-method view-type="local"
     */
    public Date getTimeAsDate() {
        return new Date(getTime());
    }

    /**
     *
     * @ejb.create-method view-type="local"
     */
    public String ejbCreate(String id, int hashVersion, String alg, String hash, String signature, Date time, String dbKey, String dbType, String keyRef, String keyType) throws CreateException {
        setId(id);
        setVersion(CURRENT_VERSION);
        setHashVersion(hashVersion);
        setProtectionAlg(alg);
        setHash(hash);
        setSignature(signature);
        setTime(time.getTime());
        setDbKey(dbKey);
        setDbType(dbType);
        setKeyRef(keyRef);
        setKeyType(keyType);
        return null;
    }

    /**
     */
    public void ejbPostCreate(String id, int hashVersion, String alg, String hash, String signature, Date time, String dbKey, String dbType, String keyRef, String keyType) {
    	// Do nothing. Required.
    }
}

