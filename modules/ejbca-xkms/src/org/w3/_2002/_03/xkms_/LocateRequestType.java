
package org.w3._2002._03.xkms_;

import javax.xml.bind.annotation.XmlAccessType;
import javax.xml.bind.annotation.XmlAccessorType;
import javax.xml.bind.annotation.XmlElement;
import javax.xml.bind.annotation.XmlRootElement;
import javax.xml.bind.annotation.XmlType;


/**
 * <p>Java class for LocateRequestType complex type.
 * 
 * <p>The following schema fragment specifies the expected content contained within this class.
 * 
 * <pre>
 * &lt;complexType name="LocateRequestType">
 *   &lt;complexContent>
 *     &lt;extension base="{http://www.w3.org/2002/03/xkms#}RequestAbstractType">
 *       &lt;sequence>
 *         &lt;element ref="{http://www.w3.org/2002/03/xkms#}QueryKeyBinding"/>
 *       &lt;/sequence>
 *     &lt;/extension>
 *   &lt;/complexContent>
 * &lt;/complexType>
 * </pre>
 * 
 * 
 */
@XmlRootElement
@XmlAccessorType(XmlAccessType.FIELD)
@XmlType(name = "LocateRequestType", propOrder = {
    "queryKeyBinding"
})
public class LocateRequestType
    extends RequestAbstractType
{

    @XmlElement(name = "QueryKeyBinding", required = true)
    protected QueryKeyBindingType queryKeyBinding;

    /**
     * Gets the value of the queryKeyBinding property.
     * 
     * @return
     *     possible object is
     *     {@link QueryKeyBindingType }
     *     
     */
    public QueryKeyBindingType getQueryKeyBinding() {
        return queryKeyBinding;
    }

    /**
     * Sets the value of the queryKeyBinding property.
     * 
     * @param value
     *     allowed object is
     *     {@link QueryKeyBindingType }
     *     
     */
    public void setQueryKeyBinding(QueryKeyBindingType value) {
        this.queryKeyBinding = value;
    }

}
