
package org.ejbca.core.protocol.ws.client.gen;

import java.util.ArrayList;
import java.util.List;
import javax.xml.bind.annotation.XmlAccessType;
import javax.xml.bind.annotation.XmlAccessorType;
import javax.xml.bind.annotation.XmlElement;
import javax.xml.bind.annotation.XmlType;


/**
 * <p>Java class for userDataSourceVOWS complex type.
 * 
 * <p>The following schema fragment specifies the expected content contained within this class.
 * 
 * <pre>
 * &lt;complexType name="userDataSourceVOWS">
 *   &lt;complexContent>
 *     &lt;restriction base="{http://www.w3.org/2001/XMLSchema}anyType">
 *       &lt;sequence>
 *         &lt;element name="isModifyable" type="{http://www.w3.org/2001/XMLSchema}int" maxOccurs="unbounded" minOccurs="0"/>
 *         &lt;element name="userDataVOWS" type="{http://ws.protocol.core.ejbca.org/}userDataVOWS" minOccurs="0"/>
 *       &lt;/sequence>
 *     &lt;/restriction>
 *   &lt;/complexContent>
 * &lt;/complexType>
 * </pre>
 * 
 * 
 */
@XmlAccessorType(XmlAccessType.FIELD)
@XmlType(name = "userDataSourceVOWS", propOrder = {
    "isModifyable",
    "userDataVOWS"
})
public class UserDataSourceVOWS {

    @XmlElement(required = true, nillable = true)
    protected List<Integer> isModifyable;
    protected UserDataVOWS userDataVOWS;

    /**
     * Gets the value of the isModifyable property.
     * 
     * <p>
     * This accessor method returns a reference to the live list,
     * not a snapshot. Therefore any modification you make to the
     * returned list will be present inside the JAXB object.
     * This is why there is not a <CODE>set</CODE> method for the isModifyable property.
     * 
     * <p>
     * For example, to add a new item, do as follows:
     * <pre>
     *    getIsModifyable().add(newItem);
     * </pre>
     * 
     * 
     * <p>
     * Objects of the following type(s) are allowed in the list
     * {@link Integer }
     * 
     * 
     */
    public List<Integer> getIsModifyable() {
        if (isModifyable == null) {
            isModifyable = new ArrayList<Integer>();
        }
        return this.isModifyable;
    }

    /**
     * Gets the value of the userDataVOWS property.
     * 
     * @return
     *     possible object is
     *     {@link UserDataVOWS }
     *     
     */
    public UserDataVOWS getUserDataVOWS() {
        return userDataVOWS;
    }

    /**
     * Sets the value of the userDataVOWS property.
     * 
     * @param value
     *     allowed object is
     *     {@link UserDataVOWS }
     *     
     */
    public void setUserDataVOWS(UserDataVOWS value) {
        this.userDataVOWS = value;
    }

}
