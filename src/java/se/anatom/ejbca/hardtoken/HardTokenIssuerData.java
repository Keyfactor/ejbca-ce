/*
 * HardTokenIssuerData.java
 *
 * Created on den 19 januari 2003, 13:11
 */

package se.anatom.ejbca.hardtoken;


/**
 *  This is a value class containing the data relating to a hard token issuer sent between 
 *  server and clients.
 * 
 *
 * @author  TomSelleck
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
