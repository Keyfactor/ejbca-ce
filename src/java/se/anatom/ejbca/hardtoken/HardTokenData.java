package se.anatom.ejbca.hardtoken;

import java.util.Date;

import se.anatom.ejbca.hardtoken.hardtokentypes.HardToken;
import se.anatom.ejbca.util.StringTools;

/**
 *  This is a value class containing the data relating to a hard token sent between
 *  server and clients.
 *
 * @author  TomSelleck
 * @version $Id: HardTokenData.java,v 1.2 2003-02-27 08:43:24 anatom Exp $
 */

public class HardTokenData implements java.io.Serializable {

    // Public Constructors
    public HardTokenData(String tokensn, String username, Date createtime,  Date modifytime, int tokentype, HardToken hardtoken){
      this.tokensn=tokensn;
      this.username=StringTools.strip(username);
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
    public void setUsername(String username){ this.username=StringTools.strip(username); }

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
