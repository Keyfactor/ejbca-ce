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

package se.anatom.ejbca.hardtoken;

import javax.ejb.CreateException;
import java.util.HashMap;
import java.util.Date;
import org.apache.log4j.Logger;
import se.anatom.ejbca.hardtoken.hardtokentypes.*;
import se.anatom.ejbca.BaseEntityBean;
import se.anatom.ejbca.SecConst;
import se.anatom.ejbca.util.StringTools;

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
 *   local-jndi-name="HardTokenDataLocal"
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
 * @ejb.home
 *   generate="local"
 *   local-extends="javax.ejb.EJBLocalHome"
 *   local-class="se.anatom.ejbca.hardtoken.HardTokenDataLocalHome"
 *
 * @ejb.interface
 *   generate="local"
 *   local-extends="javax.ejb.EJBLocalObject"
 *   local-class="se.anatom.ejbca.hardtoken.HardTokenDataLocal"
 *
 * @ejb.finder
 *   description="findByUsername"
 *   signature="Collection findByUsername(java.lang.String username)"
 *   query="SELECT DISTINCT OBJECT(a) from HardTokenDataBean a WHERE a.username=?1"
 *
 * @ejb.transaction
 *   type="Supports"
 *
 * @jonas.jdbc-mapping
 *   jndi-name="${datasource.jndi-name}"
 */
public abstract class HardTokenDataBean extends BaseEntityBean {



    private static final Logger log = Logger.getLogger(HardTokenIssuerDataBean.class);

    /**
     * @ejb.pk-field
     * @ejb.persistence
     * @ejb.interface-method view-type="local"
     */
    public abstract String getTokenSN();

    /**
     * @ejb.persistence
     */
    public abstract void setTokenSN(String tokensn);

    /**
     * @ejb.persistence
     * @ejb.interface-method view-type="local"
     */
    public abstract String getUsername();

    /**
     * username must be called 'striped' using StringTools.strip()
     * @see se.anatom.ejbca.util.StringTools
     * @ejb.persistence
     * @ejb.interface-method view-type="local"
     */
    public abstract void setUsername(String username);

    /**
     * @ejb.persistence column-name="cTime"
     */
    public abstract long getCtime();

    /**
     * @ejb.persistence column-name="cTime"
     */
    public abstract void setCtime(long createtime);

    /**
     * @ejb.persistence column-name="mTime"
     */
    public abstract long getMtime();

    /**
     * @ejb.persistence column-name="mTime"
     */
    public abstract void setMtime(long modifytime);

    /**
     * @ejb.persistence
     * @ejb.interface-method view-type="local"
     */
    public abstract int getTokenType();

    /**
     * @ejb.persistence
     * @ejb.interface-method view-type="local"
     */
    public abstract void setTokenType(int tokentype);

    /**
     * @ejb.persistence
     * @ejb.interface-method view-type="local"
     */
    public abstract String getSignificantIssuerDN();

    /**
     * @ejb.persistence
     * @ejb.interface-method view-type="local"
     */
    public abstract void setSignificantIssuerDN(String significantissuerdn);

    /**
     * @ejb.persistence
     */
    public abstract HashMap getData();

    /**
     * @ejb.persistence
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
    public HardToken getHardToken(){
      HardToken returnval = null;
      HashMap data = getData();
      int tokentype = ((Integer) data.get(HardToken.TOKENTYPE)).intValue();

      switch(tokentype){
          case SecConst.TOKEN_SWEDISHEID :
      	     returnval = new SwedishEIDHardToken();
      	     break;
          case SecConst.TOKEN_ENHANCEDEID :
      	     returnval = new EnhancedEIDHardToken();
      	     break;
          case SecConst.TOKEN_EID :    // Left for backward compability
             returnval = new EIDHardToken();
             break;
          default:
             returnval = new EIDHardToken();
             break;
      }

      returnval.loadData(data);
      return returnval;
    }

    /**
     * Method that saves the hard token issuer data to database.
     * @ejb.interface-method view-type="local"
     */
    public void setHardToken(HardToken tokendata){
       setData((HashMap) tokendata.saveData());
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
    public String ejbCreate(String tokensn, String username, Date createtime, Date modifytime, int tokentype, String significantissuerdn, HardToken tokendata) throws CreateException {
        setTokenSN(tokensn);
        setUsername(StringTools.strip(username));
        setCtime(createtime.getTime());
        setMtime(modifytime.getTime());
        setTokenType(tokentype);
        setSignificantIssuerDN(significantissuerdn);
        setHardToken(tokendata);

        log.debug("Created Hard Token "+ tokensn );
        return tokensn;
    }

    public void ejbPostCreate(String tokensn, String username, Date createtime, Date modifytime, int tokentype, String significantissuerdn, HardToken tokendata) {
        // Do nothing. Required.
    }
}
