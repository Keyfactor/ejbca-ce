package se.anatom.ejbca.hardtoken;

import javax.ejb.EntityContext;
import javax.ejb.CreateException;

import org.apache.log4j.Logger;
import se.anatom.ejbca.BaseEntityBean;

/** Entity bean should not be used directly, use though Session beans.
 *
 * Entity Bean representing certificates placed on a token.
 * Information stored:
 * <pre>
 *  certificatefingerprint 
 *  tokensn 
 * </pre>
 *
 * @version $Id: HardTokenCertificateMapBean.java,v 1.5 2003-02-28 09:25:16 koen_serry Exp $
 */
public abstract class HardTokenCertificateMapBean extends BaseEntityBean {



    private static Logger log = Logger.getLogger(HardTokenIssuerDataBean.class);

    public abstract String getCertificateFingerprint();
    public abstract void setCertificateFingerprint(String certificatefingerprint);   
        
    public abstract String getTokenSN();
    public abstract void setTokenSN(String tokensn);

     
    //
    // Fields required by Container
    //


    /**
     * Entity Bean holding data of a certificate to hard token relation.
     *
     * @return null
     *
     **/

    public String ejbCreate(String certificatefingerprint, String tokensn) throws CreateException {        
        setCertificateFingerprint(certificatefingerprint);   
        setTokenSN(tokensn);
        
        log.debug("Created HardTokenCertificateMap for token SN: "+ tokensn );
        return certificatefingerprint;
    }

    public void ejbPostCreate(String certificatefingerprint, String tokensn) {
        // Do nothing. Required.
    }
}
