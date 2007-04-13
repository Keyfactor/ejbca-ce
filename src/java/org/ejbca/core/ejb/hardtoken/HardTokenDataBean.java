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

package org.ejbca.core.ejb.hardtoken;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.util.Date;
import java.util.HashMap;

import javax.ejb.CreateException;
import javax.ejb.EJBException;

import org.apache.log4j.Logger;
import org.ejbca.core.ejb.BaseEntityBean;
import org.ejbca.core.ejb.ca.sign.ISignSessionLocal;
import org.ejbca.core.model.SecConst;
import org.ejbca.core.model.ca.caadmin.extendedcaservices.HardTokenEncryptCAServiceRequest;
import org.ejbca.core.model.ca.caadmin.extendedcaservices.HardTokenEncryptCAServiceResponse;
import org.ejbca.core.model.hardtoken.types.EIDHardToken;
import org.ejbca.core.model.hardtoken.types.EnhancedEIDHardToken;
import org.ejbca.core.model.hardtoken.types.HardToken;
import org.ejbca.core.model.hardtoken.types.SwedishEIDHardToken;
import org.ejbca.core.model.hardtoken.types.TurkishEIDHardToken;
import org.ejbca.core.model.log.Admin;
import org.ejbca.util.StringTools;


/**
 * Entity bean should not be used directly, use though Session beans.
 *
 * Entity Bean representing a hard token in the ra.
 * Information stored:
 * <pre>
 *  tokenSN (Primary key)
 *  cTime (createtime)
 *  username (username)
 *  mTime (modifytime)
 *  tokenType  (tokentype)
 *  significantissuerdn (significantissuerdn), the CA the toke should belong to.
 *  data (Data saved concerning the hard token)
 * </pre>
 *
 *
 * @ejb.bean
 *	 xxxxgenerate="false"
 *   description="This enterprise bean entity represents a hard token with accompanying data"
 *   display-name="HardTokenDataEB"
 *   name="HardTokenData"
 *   jndi-name="HardTokenData"
 *   view-type="local"
 *   type="CMP"
 *   reentrant="False"
 *   cmp-version="2.x"
 *   transaction-type="Container"
 *   schema="HardTokenDataBean"
 *   primkey-field="tokenSN"
 *
 * @ejb.pk generate="false"
 *   class="java.lang.String"
 *
 * @ejb.persistence table-name = "HardTokenData"
 * 
 * @ejb.home
 *   generate="local"
 *   local-extends="javax.ejb.EJBLocalHome"
 *   local-class="org.ejbca.core.ejb.hardtoken.HardTokenDataLocalHome"
 *
 * @ejb.interface
 *   generate="local"
 *   local-extends="javax.ejb.EJBLocalObject"
 *   local-class="org.ejbca.core.ejb.hardtoken.HardTokenDataLocal"
 *
 * @ejb.finder
 *   description="findByUsername"
 *   signature="Collection findByUsername(java.lang.String username)"
 *   query="SELECT OBJECT(a) from HardTokenDataBean a WHERE a.username=?1"
 *
 * @ejb.transaction type="Required"
 *
 * @jonas.jdbc-mapping
 *   jndi-name="${datasource.jndi-name}"
 */
public abstract class HardTokenDataBean extends BaseEntityBean {

    private static final String ENCRYPTEDDATA = "ENCRYPTEDDATA";
 
    private static final Logger log = Logger.getLogger(HardTokenIssuerDataBean.class);

    /**
     * @ejb.pk-field
     * @ejb.persistence column-name="tokenSN"
     * @ejb.interface-method view-type="local"
     */
    public abstract String getTokenSN();

    /**
     */
    public abstract void setTokenSN(String tokensn);

    /**
     * @ejb.persistence column-name="username"
     * @ejb.interface-method view-type="local"
     */
    public abstract String getUsername();

    /**
     * username must be called 'striped' using StringTools.strip()
     * @see org.ejbca.util.StringTools
     * @ejb.interface-method view-type="local"
     */
    public abstract void setUsername(String username);

    /**
     * @ejb.persistence column-name="cTime"
     */
    public abstract long getCtime();

    /**
     */
    public abstract void setCtime(long createtime);

    /**
     * @ejb.persistence column-name="mTime"
     */
    public abstract long getMtime();

    /**
     */
    public abstract void setMtime(long modifytime);

    /**
     * @ejb.persistence column-name="tokenType"
     * @ejb.interface-method view-type="local"
     */
    public abstract int getTokenType();

    /**
     * @ejb.interface-method view-type="local"
     */
    public abstract void setTokenType(int tokentype);

    /**
     * @ejb.persistence column-name="significantIssuerDN"
     * @ejb.interface-method view-type="local"
     */
    public abstract String getSignificantIssuerDN();

    /**
     * @ejb.interface-method view-type="local"
     */
    public abstract void setSignificantIssuerDN(String significantissuerdn);

    /**
     * @ejb.persistence column-name="data"
     * @weblogic.ora.columntyp@
     */
    public abstract HashMap getData();

    /**
     */
    public abstract void setData(HashMap data);

    /**
     * @ejb.interface-method view-type="local"
     */
    public Date getCreateTime(){ return new Date(getCtime()); }

    /**
     * @ejb.interface-method view-type="local"
     */
    public void setCreateTime(Date createtime){ setCtime(createtime.getTime()); }

    /**
     * @ejb.interface-method view-type="local"
     */
    public Date getModifyTime(){ return new Date(getCtime()); }

    /**
     * @ejb.interface-method view-type="local"
     */
    public void setModifyTime(Date modifytime){ setMtime(modifytime.getTime()); }

    /**
     * Method that returns the hard token issuer data and updates it if nessesary.
     * @ejb.interface-method view-type="local"
     */
    public HardToken getHardToken(Admin admin, ISignSessionLocal signsession, int encryptcaid, boolean includePUK){
      HardToken returnval = null;
      HashMap data = getData();
      
      if(data.get(ENCRYPTEDDATA) != null){
    	  // Data in encrypted, decrypt
    	  byte[] encdata = (byte[]) data.get(ENCRYPTEDDATA);
    	  
    	  HardTokenEncryptCAServiceRequest request = new HardTokenEncryptCAServiceRequest(HardTokenEncryptCAServiceRequest.COMMAND_DECRYPTDATA,encdata);
    	  try {
    		HardTokenEncryptCAServiceResponse response = (HardTokenEncryptCAServiceResponse) signsession.extendedService(admin, encryptcaid, request);
			ObjectInputStream ois = new ObjectInputStream(new ByteArrayInputStream(response.getData()));
			data = (HashMap) ois.readObject();
		} catch (Exception e) {
			throw new EJBException(e);
		}
      }      
      
      int tokentype = ((Integer) data.get(HardToken.TOKENTYPE)).intValue();

      switch(tokentype){
          case SecConst.TOKEN_SWEDISHEID :
      	     returnval = new SwedishEIDHardToken(includePUK);
      	     break;
          case SecConst.TOKEN_ENHANCEDEID :
      	     returnval = new EnhancedEIDHardToken(includePUK);
      	     break;
          case SecConst.TOKEN_TURKISHEID :
       	     returnval = new TurkishEIDHardToken(includePUK);
       	     break;
          case SecConst.TOKEN_EID :    // Left for backward compability
             returnval = new EIDHardToken(includePUK);
             break;
          default:
             returnval = new EIDHardToken(includePUK);
             break;
      }

      returnval.loadData(data);
      return returnval;
    }

    /**
     * Method that saves the hard token issuer data to database.
     * @ejb.interface-method view-type="local"
     */
    public void setHardToken(Admin admin, ISignSessionLocal signsession, int encryptcaid, HardToken tokendata){
    	if(encryptcaid != 0){
    		try {
    			ByteArrayOutputStream baos = new ByteArrayOutputStream();    	   
    			ObjectOutputStream ois = new ObjectOutputStream(baos);
    			ois.writeObject(tokendata.saveData());
    			HardTokenEncryptCAServiceRequest request = new HardTokenEncryptCAServiceRequest(HardTokenEncryptCAServiceRequest.COMMAND_ENCRYPTDATA,baos.toByteArray());
    			HardTokenEncryptCAServiceResponse response = (HardTokenEncryptCAServiceResponse) signsession.extendedService(admin, encryptcaid, request);
    			HashMap data = new HashMap();
    			data.put(ENCRYPTEDDATA, response.getData());
    			setData(data);
    		} catch (Exception e) {
    			new EJBException(e);
    		}
    	}else{
    		// Don't encrypt data
    		setData((HashMap) tokendata.saveData());
    	}
    }


    //
    // Fields required by Container
    //


    /**
     * Entity Bean holding data of a ahrd token issuer.
     *
     * @return null
     * @ejb.create-method view-type="local"
	 */
    public String ejbCreate(Admin admin, ISignSessionLocal signsession, int encryptcaid,String tokensn, String username, Date createtime, Date modifytime, int tokentype, String significantissuerdn, HardToken tokendata) throws CreateException {
        setTokenSN(tokensn);
        setUsername(StringTools.strip(username));
        setCtime(createtime.getTime());
        setMtime(modifytime.getTime());
        setTokenType(tokentype);
        setSignificantIssuerDN(significantissuerdn);
        setHardToken(admin,signsession,encryptcaid,tokendata);

        log.debug("Created Hard Token "+ tokensn );
        return tokensn;
    }

    public void ejbPostCreate(Admin admin, ISignSessionLocal signsession, int encryptcaid,String tokensn, String username, Date createtime, Date modifytime, int tokentype, String significantissuerdn, HardToken tokendata) {
        // Do nothing. Required.
    }
}
