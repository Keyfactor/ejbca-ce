/*
 * HardTokenIssuerData.java
 *
 * Created on den 19 januari 2003, 13:11
 */
package se.anatom.ejbca.hardtoken;

import java.math.BigInteger;


/**
 * This is a value class containing the data relating to a hard token issuer sent between  server
 * and clients.
 *
 * @author TomSelleck
 */
public class HardTokenIssuerData implements java.io.Serializable, Comparable {
    // Public Constants
    // Indicates the type of administrator.
    // Public Constructors
    public HardTokenIssuerData(int hardtokenissuerid, String alias, BigInteger certificatesn,
        String issuerdn, HardTokenIssuer hardtokenissuer) {
        this.hardtokenissuerid = hardtokenissuerid;
        this.alias = alias;
        this.certificatesn = certificatesn;
        this.issuerdn = issuerdn;
        this.hardtokenissuer = hardtokenissuer;
    }

    // Public Methods
    public int getHardTokenIssuerId() {
        return this.hardtokenissuerid;
    }

    /**
     * DOCUMENT ME!
     *
     * @param hardtokenissuerid DOCUMENT ME!
     */
    public void setHardTokenIssuerId(int hardtokenissuerid) {
        this.hardtokenissuerid = hardtokenissuerid;
    }

    /**
     * DOCUMENT ME!
     *
     * @return DOCUMENT ME!
     */
    public String getAlias() {
        return this.alias;
    }

    /**
     * DOCUMENT ME!
     *
     * @param alias DOCUMENT ME!
     */
    public void setAlias(String alias) {
        this.alias = alias;
    }

    /**
     * DOCUMENT ME!
     *
     * @return DOCUMENT ME!
     */
    public BigInteger getCertificateSN() {
        return this.certificatesn;
    }

    /**
     * DOCUMENT ME!
     *
     * @param certificatesn DOCUMENT ME!
     */
    public void setCertificateSN(BigInteger certificatesn) {
        this.certificatesn = certificatesn;
    }

    /**
     * DOCUMENT ME!
     *
     * @return DOCUMENT ME!
     */
    public String getIssuerSN() {
        return this.issuerdn;
    }

    /**
     * DOCUMENT ME!
     *
     * @param issuerdn DOCUMENT ME!
     */
    public void setIssuerSN(String issuerdn) {
        this.issuerdn = issuerdn;
    }

    /**
     * DOCUMENT ME!
     *
     * @return DOCUMENT ME!
     */
    public HardTokenIssuer getHardTokenIssuer() {
        return this.hardtokenissuer;
    }

    /**
     * DOCUMENT ME!
     *
     * @param hardtokenissuer DOCUMENT ME!
     */
    public void setHardTokenIssuer(HardTokenIssuer hardtokenissuer) {
        this.hardtokenissuer = hardtokenissuer;
    }

    /**
     * DOCUMENT ME!
     *
     * @param obj DOCUMENT ME!
     *
     * @return DOCUMENT ME!
     */
    public int compareTo(Object obj) {
        return this.alias.compareTo(((HardTokenIssuerData) obj).getAlias());
    }

    // Private fields
    private int hardtokenissuerid;
    private String alias;
    private BigInteger certificatesn;
    private String issuerdn;
    private HardTokenIssuer hardtokenissuer;
}
