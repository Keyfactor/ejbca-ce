/*
 * HardTokenIssuerData.java
 *
 * Created on den 19 januari 2003, 13:11
 */

package se.anatom.ejbca.hardtoken;

import java.math.BigInteger;

/**
 *  This is a value class containing the data relating to a hard token issuer sent between 
 *  server and clients.
 *
 * @author  TomSelleck
 */
public class HardTokenIssuerData implements java.io.Serializable, Comparable {
  
    // Public Constants
    // Indicates the type of administrator.
 
    // Public Constructors
    public HardTokenIssuerData(int hardtokenissuerid, String alias, BigInteger certificatesn, String issuerdn, HardTokenIssuer hardtokenissuer){
      this.hardtokenissuerid=hardtokenissuerid;
      this.alias=alias;     
      this.certificatesn=certificatesn;
      this.issuerdn=issuerdn;
      this.hardtokenissuer=hardtokenissuer;
    }
    
    // Public Methods    
    
    public int getHardTokenIssuerId(){ return this.hardtokenissuerid; }   
    public void setHardTokenIssuerId(int hardtokenissuerid){ this.hardtokenissuerid=hardtokenissuerid; }
    
    public String getAlias(){ return this.alias; }   
    public void setAlias(String alias){ this.alias=alias; }
    
    public BigInteger getCertificateSN(){ return this.certificatesn; }   
    public void setCertificateSN(BigInteger certificatesn){ this.certificatesn=certificatesn; }
    
    public String getIssuerSN(){ return this.issuerdn; }   
    public void setIssuerSN(String issuerdn){ this.issuerdn=issuerdn;}    
   
    public HardTokenIssuer getHardTokenIssuer(){ return this.hardtokenissuer; }   
    public void setHardTokenIssuer(HardTokenIssuer hardtokenissuer){ this.hardtokenissuer=hardtokenissuer; }    
       
    public int compareTo(Object obj) {
      return this.alias.compareTo( ((HardTokenIssuerData) obj).getAlias()); 
    }
    
    // Private fields
    private    int             hardtokenissuerid;
    private    String          alias;   
    private    BigInteger      certificatesn;
    private    String          issuerdn;
    private    HardTokenIssuer hardtokenissuer;
}
