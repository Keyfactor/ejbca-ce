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
 *  data (Data saved concerning the hard token)
 * </pre>
 *
 * @version $Id: HardTokenDataBean.java,v 1.5 2003-03-01 14:48:55 anatom Exp $
 */
public abstract class HardTokenDataBean extends BaseEntityBean {



    private static Logger log = Logger.getLogger(HardTokenIssuerDataBean.class);

    public abstract String getTokenSN();
    public abstract void setTokenSN(String tokensn);

    public abstract String getUsername();
    /** username must be called 'striped' using StringTools.strip()
    * @see se.anatom.ejbca.util.StringTools
    */
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
        setUsername(StringTools.strip(username));
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
}
