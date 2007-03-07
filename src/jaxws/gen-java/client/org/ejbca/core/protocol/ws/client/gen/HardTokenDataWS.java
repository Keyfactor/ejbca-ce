
package org.ejbca.core.protocol.ws.client.gen;

import java.util.ArrayList;
import java.util.List;
import javax.xml.bind.annotation.XmlAccessType;
import javax.xml.bind.annotation.XmlAccessorType;
import javax.xml.bind.annotation.XmlElement;
import javax.xml.bind.annotation.XmlType;


/**
 * <p>Java class for hardTokenDataWS complex type.
 * 
 * <p>The following schema fragment specifies the expected content contained within this class.
 * 
 * <pre>
 * &lt;complexType name="hardTokenDataWS">
 *   &lt;complexContent>
 *     &lt;restriction base="{http://www.w3.org/2001/XMLSchema}anyType">
 *       &lt;sequence>
 *         &lt;element name="certificates" type="{http://ws.protocol.core.ejbca.org/}certificate" maxOccurs="unbounded" minOccurs="0"/>
 *         &lt;element name="copies" type="{http://www.w3.org/2001/XMLSchema}string" maxOccurs="unbounded" minOccurs="0"/>
 *         &lt;element name="copyOfSN" type="{http://www.w3.org/2001/XMLSchema}string" minOccurs="0"/>
 *         &lt;element name="encKeyKeyRecoverable" type="{http://www.w3.org/2001/XMLSchema}boolean"/>
 *         &lt;element name="hardTokenSN" type="{http://www.w3.org/2001/XMLSchema}string" minOccurs="0"/>
 *         &lt;element name="pinDatas" type="{http://ws.protocol.core.ejbca.org/}pinDataWS" maxOccurs="unbounded" minOccurs="0"/>
 *         &lt;element name="tokenType" type="{http://www.w3.org/2001/XMLSchema}int"/>
 *       &lt;/sequence>
 *     &lt;/restriction>
 *   &lt;/complexContent>
 * &lt;/complexType>
 * </pre>
 * 
 * 
 */
@XmlAccessorType(XmlAccessType.FIELD)
@XmlType(name = "hardTokenDataWS", propOrder = {
    "certificates",
    "copies",
    "copyOfSN",
    "encKeyKeyRecoverable",
    "hardTokenSN",
    "pinDatas",
    "tokenType"
})
public class HardTokenDataWS {

    @XmlElement(required = true, nillable = true)
    protected List<Certificate> certificates;
    @XmlElement(required = true, nillable = true)
    protected List<String> copies;
    protected String copyOfSN;
    protected boolean encKeyKeyRecoverable;
    protected String hardTokenSN;
    @XmlElement(required = true, nillable = true)
    protected List<PinDataWS> pinDatas;
    protected int tokenType;

    /**
     * Gets the value of the certificates property.
     * 
     * <p>
     * This accessor method returns a reference to the live list,
     * not a snapshot. Therefore any modification you make to the
     * returned list will be present inside the JAXB object.
     * This is why there is not a <CODE>set</CODE> method for the certificates property.
     * 
     * <p>
     * For example, to add a new item, do as follows:
     * <pre>
     *    getCertificates().add(newItem);
     * </pre>
     * 
     * 
     * <p>
     * Objects of the following type(s) are allowed in the list
     * {@link Certificate }
     * 
     * 
     */
    public List<Certificate> getCertificates() {
        if (certificates == null) {
            certificates = new ArrayList<Certificate>();
        }
        return this.certificates;
    }

    /**
     * Gets the value of the copies property.
     * 
     * <p>
     * This accessor method returns a reference to the live list,
     * not a snapshot. Therefore any modification you make to the
     * returned list will be present inside the JAXB object.
     * This is why there is not a <CODE>set</CODE> method for the copies property.
     * 
     * <p>
     * For example, to add a new item, do as follows:
     * <pre>
     *    getCopies().add(newItem);
     * </pre>
     * 
     * 
     * <p>
     * Objects of the following type(s) are allowed in the list
     * {@link String }
     * 
     * 
     */
    public List<String> getCopies() {
        if (copies == null) {
            copies = new ArrayList<String>();
        }
        return this.copies;
    }

    /**
     * Gets the value of the copyOfSN property.
     * 
     * @return
     *     possible object is
     *     {@link String }
     *     
     */
    public String getCopyOfSN() {
        return copyOfSN;
    }

    /**
     * Sets the value of the copyOfSN property.
     * 
     * @param value
     *     allowed object is
     *     {@link String }
     *     
     */
    public void setCopyOfSN(String value) {
        this.copyOfSN = value;
    }

    /**
     * Gets the value of the encKeyKeyRecoverable property.
     * 
     */
    public boolean isEncKeyKeyRecoverable() {
        return encKeyKeyRecoverable;
    }

    /**
     * Sets the value of the encKeyKeyRecoverable property.
     * 
     */
    public void setEncKeyKeyRecoverable(boolean value) {
        this.encKeyKeyRecoverable = value;
    }

    /**
     * Gets the value of the hardTokenSN property.
     * 
     * @return
     *     possible object is
     *     {@link String }
     *     
     */
    public String getHardTokenSN() {
        return hardTokenSN;
    }

    /**
     * Sets the value of the hardTokenSN property.
     * 
     * @param value
     *     allowed object is
     *     {@link String }
     *     
     */
    public void setHardTokenSN(String value) {
        this.hardTokenSN = value;
    }

    /**
     * Gets the value of the pinDatas property.
     * 
     * <p>
     * This accessor method returns a reference to the live list,
     * not a snapshot. Therefore any modification you make to the
     * returned list will be present inside the JAXB object.
     * This is why there is not a <CODE>set</CODE> method for the pinDatas property.
     * 
     * <p>
     * For example, to add a new item, do as follows:
     * <pre>
     *    getPinDatas().add(newItem);
     * </pre>
     * 
     * 
     * <p>
     * Objects of the following type(s) are allowed in the list
     * {@link PinDataWS }
     * 
     * 
     */
    public List<PinDataWS> getPinDatas() {
        if (pinDatas == null) {
            pinDatas = new ArrayList<PinDataWS>();
        }
        return this.pinDatas;
    }

    /**
     * Gets the value of the tokenType property.
     * 
     */
    public int getTokenType() {
        return tokenType;
    }

    /**
     * Sets the value of the tokenType property.
     * 
     */
    public void setTokenType(int value) {
        this.tokenType = value;
    }

}
