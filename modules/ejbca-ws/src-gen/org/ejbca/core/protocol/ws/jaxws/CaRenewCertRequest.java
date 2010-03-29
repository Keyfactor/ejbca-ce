
package org.ejbca.core.protocol.ws.jaxws;

import java.util.List;
import javax.xml.bind.annotation.XmlAccessType;
import javax.xml.bind.annotation.XmlAccessorType;
import javax.xml.bind.annotation.XmlElement;
import javax.xml.bind.annotation.XmlRootElement;
import javax.xml.bind.annotation.XmlType;

@XmlRootElement(name = "caRenewCertRequest", namespace = "http://ws.protocol.core.ejbca.org/")
@XmlAccessorType(XmlAccessType.FIELD)
@XmlType(name = "caRenewCertRequest", namespace = "http://ws.protocol.core.ejbca.org/", propOrder = {
    "arg0",
    "arg1",
    "arg2",
    "arg3",
    "arg4",
    "arg5"
})
public class CaRenewCertRequest {

    @XmlElement(name = "arg0", namespace = "")
    private String arg0;
    @XmlElement(name = "arg1", namespace = "")
    private List<byte[]> arg1;
    @XmlElement(name = "arg2", namespace = "")
    private boolean arg2;
    @XmlElement(name = "arg3", namespace = "")
    private boolean arg3;
    @XmlElement(name = "arg4", namespace = "")
    private boolean arg4;
    @XmlElement(name = "arg5", namespace = "")
    private String arg5;

    /**
     * 
     * @return
     *     returns String
     */
    public String getArg0() {
        return this.arg0;
    }

    /**
     * 
     * @param arg0
     *     the value for the arg0 property
     */
    public void setArg0(String arg0) {
        this.arg0 = arg0;
    }

    /**
     * 
     * @return
     *     returns List<byte[]>
     */
    public List<byte[]> getArg1() {
        return this.arg1;
    }

    /**
     * 
     * @param arg1
     *     the value for the arg1 property
     */
    public void setArg1(List<byte[]> arg1) {
        this.arg1 = arg1;
    }

    /**
     * 
     * @return
     *     returns boolean
     */
    public boolean isArg2() {
        return this.arg2;
    }

    /**
     * 
     * @param arg2
     *     the value for the arg2 property
     */
    public void setArg2(boolean arg2) {
        this.arg2 = arg2;
    }

    /**
     * 
     * @return
     *     returns boolean
     */
    public boolean isArg3() {
        return this.arg3;
    }

    /**
     * 
     * @param arg3
     *     the value for the arg3 property
     */
    public void setArg3(boolean arg3) {
        this.arg3 = arg3;
    }

    /**
     * 
     * @return
     *     returns boolean
     */
    public boolean isArg4() {
        return this.arg4;
    }

    /**
     * 
     * @param arg4
     *     the value for the arg4 property
     */
    public void setArg4(boolean arg4) {
        this.arg4 = arg4;
    }

    /**
     * 
     * @return
     *     returns String
     */
    public String getArg5() {
        return this.arg5;
    }

    /**
     * 
     * @param arg5
     *     the value for the arg5 property
     */
    public void setArg5(String arg5) {
        this.arg5 = arg5;
    }

}
