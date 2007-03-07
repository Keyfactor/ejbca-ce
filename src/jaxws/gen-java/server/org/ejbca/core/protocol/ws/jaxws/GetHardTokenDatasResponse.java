
package org.ejbca.core.protocol.ws.jaxws;

import java.util.List;
import javax.xml.bind.annotation.XmlAccessType;
import javax.xml.bind.annotation.XmlAccessorType;
import javax.xml.bind.annotation.XmlElement;
import javax.xml.bind.annotation.XmlRootElement;
import javax.xml.bind.annotation.XmlType;
import org.ejbca.core.protocol.ws.objects.HardTokenDataWS;

@XmlRootElement(name = "getHardTokenDatasResponse", namespace = "http://ws.protocol.core.ejbca.org/")
@XmlAccessorType(XmlAccessType.FIELD)
@XmlType(name = "getHardTokenDatasResponse", namespace = "http://ws.protocol.core.ejbca.org/")
public class GetHardTokenDatasResponse {

    @XmlElement(name = "return", namespace = "")
    private List<HardTokenDataWS> _return;

    /**
     * 
     * @return
     *     returns List<HardTokenDataWS>
     */
    public List<HardTokenDataWS> get_return() {
        return this._return;
    }

    /**
     * 
     * @param _return
     *     the value for the _return property
     */
    public void set_return(List<HardTokenDataWS> _return) {
        this._return = _return;
    }

}
