
package org.w3._2002._03.xkms_;

import javax.xml.bind.annotation.XmlAccessType;
import javax.xml.bind.annotation.XmlAccessorType;
import javax.xml.bind.annotation.XmlElement;
import javax.xml.bind.annotation.XmlRootElement;
import javax.xml.bind.annotation.XmlType;


/**
 * <p>Java class for RSAKeyPairType complex type.
 * 
 * <p>The following schema fragment specifies the expected content contained within this class.
 * 
 * <pre>
 * &lt;complexType name="RSAKeyPairType">
 *   &lt;complexContent>
 *     &lt;restriction base="{http://www.w3.org/2001/XMLSchema}anyType">
 *       &lt;sequence>
 *         &lt;element ref="{http://www.w3.org/2002/03/xkms#}Modulus"/>
 *         &lt;element ref="{http://www.w3.org/2002/03/xkms#}Exponent"/>
 *         &lt;element ref="{http://www.w3.org/2002/03/xkms#}P"/>
 *         &lt;element ref="{http://www.w3.org/2002/03/xkms#}Q"/>
 *         &lt;element ref="{http://www.w3.org/2002/03/xkms#}DP"/>
 *         &lt;element ref="{http://www.w3.org/2002/03/xkms#}DQ"/>
 *         &lt;element ref="{http://www.w3.org/2002/03/xkms#}InverseQ"/>
 *         &lt;element ref="{http://www.w3.org/2002/03/xkms#}D"/>
 *       &lt;/sequence>
 *     &lt;/restriction>
 *   &lt;/complexContent>
 * &lt;/complexType>
 * </pre>
 * 
 * 
 */
@XmlRootElement
@XmlAccessorType(XmlAccessType.FIELD)
@XmlType(name = "RSAKeyPairType", propOrder = {
    "modulus",
    "exponent",
    "p",
    "q",
    "dp",
    "dq",
    "inverseQ",
    "d"
})
public class RSAKeyPairType {

    @XmlElement(name = "Modulus", required = true)
    protected byte[] modulus;
    @XmlElement(name = "Exponent", required = true)
    protected byte[] exponent;
    @XmlElement(name = "P", required = true)
    protected byte[] p;
    @XmlElement(name = "Q", required = true)
    protected byte[] q;
    @XmlElement(name = "DP", required = true)
    protected byte[] dp;
    @XmlElement(name = "DQ", required = true)
    protected byte[] dq;
    @XmlElement(name = "InverseQ", required = true)
    protected byte[] inverseQ;
    @XmlElement(name = "D", required = true)
    protected byte[] d;

    /**
     * Gets the value of the modulus property.
     * 
     * @return
     *     possible object is
     *     byte[]
     */
    public byte[] getModulus() {
        return modulus;
    }

    /**
     * Sets the value of the modulus property.
     * 
     * @param value
     *     allowed object is
     *     byte[]
     */
    public void setModulus(byte[] value) {
        this.modulus = ((byte[]) value);
    }

    /**
     * Gets the value of the exponent property.
     * 
     * @return
     *     possible object is
     *     byte[]
     */
    public byte[] getExponent() {
        return exponent;
    }

    /**
     * Sets the value of the exponent property.
     * 
     * @param value
     *     allowed object is
     *     byte[]
     */
    public void setExponent(byte[] value) {
        this.exponent = ((byte[]) value);
    }

    /**
     * Gets the value of the p property.
     * 
     * @return
     *     possible object is
     *     byte[]
     */
    public byte[] getP() {
        return p;
    }

    /**
     * Sets the value of the p property.
     * 
     * @param value
     *     allowed object is
     *     byte[]
     */
    public void setP(byte[] value) {
        this.p = ((byte[]) value);
    }

    /**
     * Gets the value of the q property.
     * 
     * @return
     *     possible object is
     *     byte[]
     */
    public byte[] getQ() {
        return q;
    }

    /**
     * Sets the value of the q property.
     * 
     * @param value
     *     allowed object is
     *     byte[]
     */
    public void setQ(byte[] value) {
        this.q = ((byte[]) value);
    }

    /**
     * Gets the value of the dp property.
     * 
     * @return
     *     possible object is
     *     byte[]
     */
    public byte[] getDP() {
        return dp;
    }

    /**
     * Sets the value of the dp property.
     * 
     * @param value
     *     allowed object is
     *     byte[]
     */
    public void setDP(byte[] value) {
        this.dp = ((byte[]) value);
    }

    /**
     * Gets the value of the dq property.
     * 
     * @return
     *     possible object is
     *     byte[]
     */
    public byte[] getDQ() {
        return dq;
    }

    /**
     * Sets the value of the dq property.
     * 
     * @param value
     *     allowed object is
     *     byte[]
     */
    public void setDQ(byte[] value) {
        this.dq = ((byte[]) value);
    }

    /**
     * Gets the value of the inverseQ property.
     * 
     * @return
     *     possible object is
     *     byte[]
     */
    public byte[] getInverseQ() {
        return inverseQ;
    }

    /**
     * Sets the value of the inverseQ property.
     * 
     * @param value
     *     allowed object is
     *     byte[]
     */
    public void setInverseQ(byte[] value) {
        this.inverseQ = ((byte[]) value);
    }

    /**
     * Gets the value of the d property.
     * 
     * @return
     *     possible object is
     *     byte[]
     */
    public byte[] getD() {
        return d;
    }

    /**
     * Sets the value of the d property.
     * 
     * @param value
     *     allowed object is
     *     byte[]
     */
    public void setD(byte[] value) {
        this.d = ((byte[]) value);
    }

}
