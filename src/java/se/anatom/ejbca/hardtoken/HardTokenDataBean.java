package se.anatom.ejbca.hardtoken;

import javax.ejb.EntityContext;
import javax.ejb.CreateException;
import java.util.HashMap;
import java.util.Date;
import org.apache.log4j.*;
import se.anatom.ejbca.hardtoken.hardtokentypes.*;
import se.anatom.ejbca.SecConst;

/** Entity bean should not be used directly, use though Session beans.
 *
 * Entity Bean representing a hard token in the ra.
 * Information stored:
 * <pre>
 *  tokensn (Primary key)
 *  ctime (createtime)
 *  mtime (modifytime)
 *  tokentype 
 *  tokendata (Data saved concerning the hard token)
 * </pre>
 *
 * @version $Id: HardTokenDataBean.java,v 1.1 2003-02-06 15:35:46 herrvendil Exp $
 **/

public abstract class HardTokenDataBean implements javax.ejb.EntityBean {



    private static Category log = Category.getInstance(HardTokenIssuerDataBean.class.getName() );

    protected EntityContext  ctx;
    public abstract String getTokenSN();
    public abstract void setTokenSN(String tokensn);
    
    public abstract String getUsername();
    public abstract void setUsername(String username);                  

    public abstract long getCTime();
    public abstract void setCTime(long createtime);
    
    public abstract long getMTime();
    public abstract void setMTime(long modifytime);
    
    public abstract int getTokenType();
    public abstract void setTokenType(int tokentype);    

    public abstract HashMap getData();
    public abstract void setData(HashMap data);
    
    public Date getCreateTime(){ return new Date(getCTime()); }
    
    public void setCreateTime(Date createtime){ setCTime(createtime.getTime()); } 

    public Date getModifyTime(){ return new Date(getMTime()); }
    
    public void setModifyTime(Date modifytime){ setMTime(modifytime.getTime()); } 
   
    /** 
     * Method that returns the hard token issuer data and updates it if nessesary.
     */    
    
    public HardToken getHardToken(){
      HardToken returnval = null;        
      HashMap data = getData();
      int tokentype = ((Integer) data.get(HardToken.TOKENTYPE)).intValue();
      
      switch(tokentype){
          case SecConst.TOKEN_EID :
             returnval = new EIDHardToken();
             break;
          default:
             returnval = new EIDHardToken();
             break;              
      }

      returnval.loadData((Object) data);
      return returnval;              
    }
    
    /** 
     * Method that saves the hard token issuer data to database.
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
     *
     **/

    public String ejbCreate(String tokensn, String username, Date createtime, Date modifytime, int tokentype, HardToken tokendata) throws CreateException {
        setTokenSN(tokensn);
        setUsername(username);
        setCTime(createtime.getTime());
        setMTime(modifytime.getTime());        
        setTokenType(tokentype);       
        setHardToken(tokendata);
        
        log.debug("Created Hard Token "+ tokensn );
        return tokensn;
    }

    public void ejbPostCreate(String tokensn, String username, Date createtime, Date modifytime, int tokentype, HardToken tokendata) {
        // Do nothing. Required.
    }

    public void setEntityContext(EntityContext ctx) {
        this.ctx = ctx;
    }

    public void unsetEntityContext() {
        this.ctx = null;
    }

    public void ejbActivate() {
        // Not implemented.
    }

    public void ejbPassivate() {
        // Not implemented.
    }

    public void ejbLoad() {
        // Not implemented.
    }

    public void ejbStore() {
        // Not implemented.
    }

    public void ejbRemove() {
        // Not implemented.
    }

}

