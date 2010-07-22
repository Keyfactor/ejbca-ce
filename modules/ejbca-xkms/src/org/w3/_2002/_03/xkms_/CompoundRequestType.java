
package org.w3._2002._03.xkms_;

import java.util.ArrayList;
import java.util.List;

import javax.xml.bind.annotation.XmlAccessType;
import javax.xml.bind.annotation.XmlAccessorType;
import javax.xml.bind.annotation.XmlElement;
import javax.xml.bind.annotation.XmlElements;
import javax.xml.bind.annotation.XmlType;


/**
 * <p>Java class for CompoundRequestType complex type.
 * 
 * <p>The following schema fragment specifies the expected content contained within this class.
 * 
 * <pre>
 * &lt;complexType name="CompoundRequestType">
 *   &lt;complexContent>
 *     &lt;extension base="{http://www.w3.org/2002/03/xkms#}RequestAbstractType">
 *       &lt;choice maxOccurs="unbounded">
 *         &lt;element ref="{http://www.w3.org/2002/03/xkms#}LocateRequest"/>
 *         &lt;element ref="{http://www.w3.org/2002/03/xkms#}ValidateRequest"/>
 *         &lt;element ref="{http://www.w3.org/2002/03/xkms#}RegisterRequest"/>
 *         &lt;element ref="{http://www.w3.org/2002/03/xkms#}ReissueRequest"/>
 *         &lt;element ref="{http://www.w3.org/2002/03/xkms#}RecoverRequest"/>
 *         &lt;element ref="{http://www.w3.org/2002/03/xkms#}RevokeRequest"/>
 *       &lt;/choice>
 *     &lt;/extension>
 *   &lt;/complexContent>
 * &lt;/complexType>
 * </pre>
 * 
 * 
 */
@XmlAccessorType(XmlAccessType.FIELD)
@XmlType(name = "CompoundRequestType", propOrder = {
    "locateRequestOrValidateRequestOrRegisterRequest"
})
public class CompoundRequestType
    extends RequestAbstractType
{

    @XmlElements({
        @XmlElement(name = "RecoverRequest", type = RecoverRequestType.class),
        @XmlElement(name = "LocateRequest", type = LocateRequestType.class),
        @XmlElement(name = "ValidateRequest", type = ValidateRequestType.class),
        @XmlElement(name = "RevokeRequest", type = RevokeRequestType.class),
        @XmlElement(name = "RegisterRequest", type = RegisterRequestType.class),
        @XmlElement(name = "ReissueRequest", type = ReissueRequestType.class)
    })
    protected List<RequestAbstractType> locateRequestOrValidateRequestOrRegisterRequest;

    /**
     * Gets the value of the locateRequestOrValidateRequestOrRegisterRequest property.
     * 
     * <p>
     * This accessor method returns a reference to the live list,
     * not a snapshot. Therefore any modification you make to the
     * returned list will be present inside the JAXB object.
     * This is why there is not a <CODE>set</CODE> method for the locateRequestOrValidateRequestOrRegisterRequest property.
     * 
     * <p>
     * For example, to add a new item, do as follows:
     * <pre>
     *    getLocateRequestOrValidateRequestOrRegisterRequest().add(newItem);
     * </pre>
     * 
     * 
     * <p>
     * Objects of the following type(s) are allowed in the list
     * {@link RecoverRequestType }
     * {@link LocateRequestType }
     * {@link ValidateRequestType }
     * {@link RevokeRequestType }
     * {@link RegisterRequestType }
     * {@link ReissueRequestType }
     * 
     * 
     */
    public List<RequestAbstractType> getLocateRequestOrValidateRequestOrRegisterRequest() {
        if (locateRequestOrValidateRequestOrRegisterRequest == null) {
            locateRequestOrValidateRequestOrRegisterRequest = new ArrayList<RequestAbstractType>();
        }
        return this.locateRequestOrValidateRequestOrRegisterRequest;
    }

}
