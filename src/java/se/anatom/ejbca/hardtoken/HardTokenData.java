/*
 * HardTokenData.java
 *
 * Created on den 19 januari 2003, 13:48
 */

package se.anatom.ejbca.hardtoken;

import java.util.Date;

import se.anatom.ejbca.hardtoken.hardtokentypes.HardToken;

/**
 *  This is a value class containing the data relating to a hard token sent between 
 *  server and clients.
 *
 * @author  TomSelleck
 */

public class HardTokenData implements java.io.Serializable {
  
    // Public Constructors
    public HardTokenData(String tokensn, String username, Date createtime,  Date modifytime, int tokentype, HardToken hardtoken){
      this.tokensn=tokensn;
      this.username=username;
      this.createtime=createtime;     
      this.modifytime=modifytime;
      this.tokentype=tokentype;
      this.hardtoken=hardtoken;
    }
    
    public HardTokenData(){
    }    
    
    // Public Methods    
    
    public String getTokenSN(){ return this.tokensn; }   
    public void setTokenSN(String tokensn){ this.tokensn=tokensn; }
    
    public String getUsername(){ return this.username; }   
    public void setUsername(String username){ this.username=username; }    
    
    public Date getCreateTime(){ return this.createtime; }   
    public void setCreateTime(Date createtime){ this.createtime=createtime; }
    
    public Date getModifyTime(){ return this.modifytime; }   
    public void setModifyTime(Date modifytime){ this.modifytime=modifytime; }
   
    public int getTokenType(){ return this.tokentype; }   
    public void setTokenType(int tokentype){ this.tokentype=tokentype; }    
    
    public HardToken getHardToken(){ return this.hardtoken; }   
    public void setHardToken(HardToken hardtoken){ this.hardtoken=hardtoken; }    
       
    // Private fields
    private    String          tokensn;
    private    String          username;
    private    Date            createtime;   
    private    Date            modifytime;
    private    int             tokentype;
    private    HardToken       hardtoken;
}
