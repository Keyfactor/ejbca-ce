package se.anatom.ejbca.hardtoken;

import java.math.BigInteger;

import se.anatom.ejbca.hardtoken.HardTokenIssuer;

/**
 * For docs, see HardTokenIssuerDataBean
 *
 * @version $Id: HardTokenIssuerDataLocal.java,v 1.4 2003-09-03 12:47:24 herrvendil Exp $
 **/

public interface HardTokenIssuerDataLocal extends javax.ejb.EJBLocalObject {

    // Public methods

    public Integer getId();

    public String getAlias();

    public void setAlias(String alias);
    
    public BigInteger getCertSN();
    
    public void setCertSN(BigInteger certificatesn);

    public String getCertIssuerDN();
    
    public void setCertIssuerDN(String certissuerdn);
    
    public HardTokenIssuer getHardTokenIssuer();

    public void setHardTokenIssuer(HardTokenIssuer issuerdata);
}

