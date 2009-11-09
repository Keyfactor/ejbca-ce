
package org.ejbca.core.protocol.ws.client.gen;

import javax.xml.bind.annotation.XmlAccessType;
import javax.xml.bind.annotation.XmlAccessorType;
import javax.xml.bind.annotation.XmlType;


/**
 * <p>Java class for userMatch complex type.
 * 
 * <p>The following schema fragment specifies the expected content contained within this class.
 * 
 * <pre>
 * &lt;complexType name="userMatch">
 *   &lt;complexContent>
 *     &lt;restriction base="{http://www.w3.org/2001/XMLSchema}anyType">
 *       &lt;sequence>
 *         &lt;element name="matchtype" type="{http://www.w3.org/2001/XMLSchema}int"/>
 *         &lt;element name="matchvalue" type="{http://www.w3.org/2001/XMLSchema}string" minOccurs="0"/>
 *         &lt;element name="matchwith" type="{http://www.w3.org/2001/XMLSchema}int"/>
 *       &lt;/sequence>
 *     &lt;/restriction>
 *   &lt;/complexContent>
 * &lt;/complexType>
 * </pre>
 * 
 * 
 */
@XmlAccessorType(XmlAccessType.FIELD)
@XmlType(name = "userMatch", propOrder = {
    "matchtype",
    "matchvalue",
    "matchwith"
})
public class UserMatch {

    protected int matchtype;
    protected String matchvalue;
    protected int matchwith;

    /**
     * Gets the value of the matchtype property.
     * 
     */
    public int getMatchtype() {
        return matchtype;
    }

    /**
     * Sets the value of the matchtype property.
     * 
     */
    public void setMatchtype(int value) {
        this.matchtype = value;
    }

    /**
     * Gets the value of the matchvalue property.
     * 
     * @return
     *     possible object is
     *     {@link String }
     *     
     */
    public String getMatchvalue() {
        return matchvalue;
    }

    /**
     * Sets the value of the matchvalue property.
     * 
     * @param value
     *     allowed object is
     *     {@link String }
     *     
     */
    public void setMatchvalue(String value) {
        this.matchvalue = value;
    }

    /**
     * Gets the value of the matchwith property.
     * 
     */
    public int getMatchwith() {
        return matchwith;
    }

    /**
     * Sets the value of the matchwith property.
     * 
     */
    public void setMatchwith(int value) {
        this.matchwith = value;
    }

}
