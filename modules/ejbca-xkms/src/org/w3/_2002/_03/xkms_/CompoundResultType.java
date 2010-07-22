
package org.w3._2002._03.xkms_;

import java.util.ArrayList;
import java.util.List;

import javax.xml.bind.annotation.XmlAccessType;
import javax.xml.bind.annotation.XmlAccessorType;
import javax.xml.bind.annotation.XmlElement;
import javax.xml.bind.annotation.XmlElements;
import javax.xml.bind.annotation.XmlType;


/**
 * <p>Java class for CompoundResultType complex type.
 * 
 * <p>The following schema fragment specifies the expected content contained within this class.
 * 
 * <pre>
 * &lt;complexType name="CompoundResultType">
 *   &lt;complexContent>
 *     &lt;extension base="{http://www.w3.org/2002/03/xkms#}ResultType">
 *       &lt;choice maxOccurs="unbounded" minOccurs="0">
 *         &lt;element ref="{http://www.w3.org/2002/03/xkms#}LocateResult"/>
 *         &lt;element ref="{http://www.w3.org/2002/03/xkms#}ValidateResult"/>
 *         &lt;element ref="{http://www.w3.org/2002/03/xkms#}RegisterResult"/>
 *         &lt;element ref="{http://www.w3.org/2002/03/xkms#}ReissueResult"/>
 *         &lt;element ref="{http://www.w3.org/2002/03/xkms#}RecoverResult"/>
 *         &lt;element ref="{http://www.w3.org/2002/03/xkms#}RevokeResult"/>
 *       &lt;/choice>
 *     &lt;/extension>
 *   &lt;/complexContent>
 * &lt;/complexType>
 * </pre>
 * 
 * 
 */
@XmlAccessorType(XmlAccessType.FIELD)
@XmlType(name = "CompoundResultType", propOrder = {
    "locateResultOrValidateResultOrRegisterResult"
})
public class CompoundResultType
    extends ResultType
{

    @XmlElements({
        @XmlElement(name = "RevokeResult", type = RevokeResultType.class),
        @XmlElement(name = "LocateResult", type = LocateResultType.class),
        @XmlElement(name = "RecoverResult", type = RecoverResultType.class),
        @XmlElement(name = "ReissueResult", type = ReissueResultType.class),
        @XmlElement(name = "RegisterResult", type = RegisterResultType.class),
        @XmlElement(name = "ValidateResult", type = ValidateResultType.class)
    })
    protected List<ResultType> locateResultOrValidateResultOrRegisterResult;

    /**
     * Gets the value of the locateResultOrValidateResultOrRegisterResult property.
     * 
     * <p>
     * This accessor method returns a reference to the live list,
     * not a snapshot. Therefore any modification you make to the
     * returned list will be present inside the JAXB object.
     * This is why there is not a <CODE>set</CODE> method for the locateResultOrValidateResultOrRegisterResult property.
     * 
     * <p>
     * For example, to add a new item, do as follows:
     * <pre>
     *    getLocateResultOrValidateResultOrRegisterResult().add(newItem);
     * </pre>
     * 
     * 
     * <p>
     * Objects of the following type(s) are allowed in the list
     * {@link RevokeResultType }
     * {@link LocateResultType }
     * {@link RecoverResultType }
     * {@link ReissueResultType }
     * {@link RegisterResultType }
     * {@link ValidateResultType }
     * 
     * 
     */
    public List<ResultType> getLocateResultOrValidateResultOrRegisterResult() {
        if (locateResultOrValidateResultOrRegisterResult == null) {
            locateResultOrValidateResultOrRegisterResult = new ArrayList<ResultType>();
        }
        return this.locateResultOrValidateResultOrRegisterResult;
    }

}
