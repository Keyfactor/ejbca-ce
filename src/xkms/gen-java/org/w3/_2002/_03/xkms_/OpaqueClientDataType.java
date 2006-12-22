
package org.w3._2002._03.xkms_;

import java.util.ArrayList;
import java.util.List;
import javax.xml.bind.annotation.XmlAccessType;
import javax.xml.bind.annotation.XmlAccessorType;
import javax.xml.bind.annotation.XmlElement;
import javax.xml.bind.annotation.XmlType;


/**
 * <p>Java class for OpaqueClientDataType complex type.
 * 
 * <p>The following schema fragment specifies the expected content contained within this class.
 * 
 * <pre>
 * &lt;complexType name="OpaqueClientDataType">
 *   &lt;complexContent>
 *     &lt;restriction base="{http://www.w3.org/2001/XMLSchema}anyType">
 *       &lt;sequence maxOccurs="unbounded">
 *         &lt;element ref="{http://www.w3.org/2002/03/xkms#}OpaqueData" minOccurs="0"/>
 *       &lt;/sequence>
 *     &lt;/restriction>
 *   &lt;/complexContent>
 * &lt;/complexType>
 * </pre>
 * 
 * 
 */
@XmlAccessorType(XmlAccessType.FIELD)
@XmlType(name = "OpaqueClientDataType", propOrder = {
    "opaqueData"
})
public class OpaqueClientDataType {

    @XmlElement(name = "OpaqueData")
    protected List<byte[]> opaqueData;

    /**
     * Gets the value of the opaqueData property.
     * 
     * <p>
     * This accessor method returns a reference to the live list,
     * not a snapshot. Therefore any modification you make to the
     * returned list will be present inside the JAXB object.
     * This is why there is not a <CODE>set</CODE> method for the opaqueData property.
     * 
     * <p>
     * For example, to add a new item, do as follows:
     * <pre>
     *    getOpaqueData().add(newItem);
     * </pre>
     * 
     * 
     * <p>
     * Objects of the following type(s) are allowed in the list
     * byte[]
     * 
     */
    public List<byte[]> getOpaqueData() {
        if (opaqueData == null) {
            opaqueData = new ArrayList<byte[]>();
        }
        return this.opaqueData;
    }

}
