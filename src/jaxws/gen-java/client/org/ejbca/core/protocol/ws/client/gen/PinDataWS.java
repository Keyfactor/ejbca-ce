
package org.ejbca.core.protocol.ws.client.gen;

import javax.xml.bind.annotation.XmlAccessType;
import javax.xml.bind.annotation.XmlAccessorType;
import javax.xml.bind.annotation.XmlElement;
import javax.xml.bind.annotation.XmlType;


/**
 * <p>Java class for pinDataWS complex type.
 * 
 * <p>The following schema fragment specifies the expected content contained within this class.
 * 
 * <pre>
 * &lt;complexType name="pinDataWS">
 *   &lt;complexContent>
 *     &lt;restriction base="{http://www.w3.org/2001/XMLSchema}anyType">
 *       &lt;sequence>
 *         &lt;element name="initialPIN" type="{http://www.w3.org/2001/XMLSchema}string" minOccurs="0"/>
 *         &lt;element name="PUK" type="{http://www.w3.org/2001/XMLSchema}string" minOccurs="0"/>
 *         &lt;element name="type" type="{http://www.w3.org/2001/XMLSchema}int"/>
 *       &lt;/sequence>
 *     &lt;/restriction>
 *   &lt;/complexContent>
 * &lt;/complexType>
 * </pre>
 * 
 * 
 */
@XmlAccessorType(XmlAccessType.FIELD)
@XmlType(name = "pinDataWS", propOrder = {
    "initialPIN",
    "puk",
    "type"
})
public class PinDataWS {

    protected String initialPIN;
    @XmlElement(name = "PUK")
    protected String puk;
    protected int type;

    /**
     * Gets the value of the initialPIN property.
     * 
     * @return
     *     possible object is
     *     {@link String }
     *     
     */
    public String getInitialPIN() {
        return initialPIN;
    }

    /**
     * Sets the value of the initialPIN property.
     * 
     * @param value
     *     allowed object is
     *     {@link String }
     *     
     */
    public void setInitialPIN(String value) {
        this.initialPIN = value;
    }

    /**
     * Gets the value of the puk property.
     * 
     * @return
     *     possible object is
     *     {@link String }
     *     
     */
    public String getPUK() {
        return puk;
    }

    /**
     * Sets the value of the puk property.
     * 
     * @param value
     *     allowed object is
     *     {@link String }
     *     
     */
    public void setPUK(String value) {
        this.puk = value;
    }

    /**
     * Gets the value of the type property.
     * 
     */
    public int getType() {
        return type;
    }

    /**
     * Sets the value of the type property.
     * 
     */
    public void setType(int value) {
        this.type = value;
    }

}
