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
 
/*
 * HardTokenIssuerData.java
 *
 * Created on den 19 januari 2003, 13:11
 */

package org.ejbca.core.model.hardtoken;


/**
 *  This is a value class containing the data relating to a hard token issuer sent between 
 *  server and clients.
 * 
 *
 * @author  TomSelleck
 * @version $Id$
 */
public class HardTokenIssuerData implements java.io.Serializable, Comparable {
  
    // Public Constants
    // Indicates the type of administrator.
 
    // Public Constructors
    public HardTokenIssuerData(int hardtokenissuerid, String alias, int admingroupid , HardTokenIssuer hardtokenissuer){
      this.hardtokenissuerid=hardtokenissuerid;
      this.alias=alias;     
      this.admingroupid = admingroupid; 
      this.hardtokenissuer=hardtokenissuer;
    }
    
    // Public Methods    
    
    public int getHardTokenIssuerId(){ return this.hardtokenissuerid; }   
    public void setHardTokenIssuerId(int hardtokenissuerid){ this.hardtokenissuerid=hardtokenissuerid; }
    
    public String getAlias(){ return this.alias; }   
    public void setAlias(String alias){ this.alias=alias; }
    
    public int getAdminGroupId(){ return this.admingroupid; }   
    public void setAdminGroupId(int admingroupid){ this.admingroupid=admingroupid;}
           
    public HardTokenIssuer getHardTokenIssuer(){ return this.hardtokenissuer; }   
    public void setHardTokenIssuer(HardTokenIssuer hardtokenissuer){ this.hardtokenissuer=hardtokenissuer; }    
       
    public int compareTo(Object obj) {
      return this.alias.compareTo( ((HardTokenIssuerData) obj).getAlias()); 
    }
    
    // Private fields
    private    int             hardtokenissuerid;
    private    String          alias;   
    private    int             admingroupid; 
    private    HardTokenIssuer hardtokenissuer;
}
