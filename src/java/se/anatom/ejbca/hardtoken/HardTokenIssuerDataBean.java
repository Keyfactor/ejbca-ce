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

import java.util.HashMap;

import javax.ejb.CreateException;

import org.apache.log4j.Logger;

import se.anatom.ejbca.BaseEntityBean;

/** Entity bean should not be used directly, use though Session beans.
 *
 * Entity Bean representing a hard token issuer in the ra.
 * Information stored:
 * <pre>
 *  id (Primary key)
 *  alias (of the hard token issuer)
 *  admingroupid (Integer pointing to administrator group associated to this issuer) 
 *  hardtokenissuer (Data saved concerning the hard token issuer)
 * </pre>
 *
 * @version $Id: HardTokenIssuerDataBean.java,v 1.9 2004-04-16 07:38:56 anatom Exp $
 **/

public abstract class HardTokenIssuerDataBean extends BaseEntityBean {



    private static Logger log = Logger.getLogger(HardTokenIssuerDataBean.class);

    public abstract Integer getId();
    public abstract void setId(Integer id);

    public abstract String getAlias();
    public abstract void setAlias(String alias);
    
    public abstract int getAdminGroupId();
    public abstract void setAdminGroupId(int groupid);

    public abstract HashMap getData();
    public abstract void setData(HashMap data);
    
       
    /** 
     * Method that returns the hard token issuer data and updates it if nessesary.
     */    
    
    public HardTokenIssuer getHardTokenIssuer(){
      HardTokenIssuer returnval = new HardTokenIssuer();
      returnval.loadData((Object) getData());
      return returnval;              
    }
    
    /** 
     * Method that saves the hard token issuer data to database.
     */    
    public void setHardTokenIssuer(HardTokenIssuer hardtokenissuer){
       setData((HashMap) hardtokenissuer.saveData());          
    }
    

    //
    // Fields required by Container
    //


    /**
     * Entity Bean holding data of a ahrd token issuer.
     *
     * @return null
     *
     **/

    public Integer ejbCreate(Integer id, String alias, int admingroupid,  HardTokenIssuer issuerdata) throws CreateException {
        setId(id);
        setAlias(alias);
        setAdminGroupId(admingroupid);
        setHardTokenIssuer(issuerdata);
        
        log.debug("Created Hard Token Issuer "+ alias );
        return id;
    }

    public void ejbPostCreate(Integer id, String alias, int admingroupid,  HardTokenIssuer issuerdata) {
        // Do nothing. Required.
    }
}
