package org.ejbca.core.protocol.ws.client.gen;

import java.util.ArrayList;
import java.util.List;

import javax.xml.bind.annotation.XmlAccessType;
import javax.xml.bind.annotation.XmlAccessorType;
import javax.xml.bind.annotation.XmlType;

/**
 * <p>Java class for createCryptoToken complex type.
 * 
 * <p>The following schema fragment specifies the expected content contained within this class.
 * 
 * <pre>
 * &lt;complexType name="createCryptoToken">
 *   &lt;complexContent>
 *     &lt;restriction base="{http://www.w3.org/2001/XMLSchema}anyType">
 *       &lt;sequence>
 *         &lt;element name="arg0" type="{http://www.w3.org/2001/XMLSchema}String"/>
 *         &lt;element name="arg1" type="{http://www.w3.org/2001/XMLSchema}String"/>
 *         &lt;element name="arg2" type="{http://www.w3.org/2001/XMLSchema}String"/>
 *         &lt;element name="arg3" type="{http://www.w3.org/2001/XMLSchema}boolean"/>
 *         &lt;element name="arg4" type="{http://www.w3.org/2001/XMLSchema}String" maxOccurs="unbounded" minOccurs="0"/>
 *       &lt;/sequence>
 *     &lt;/restriction>
 *   &lt;/complexContent>
 * &lt;/complexType>
 * </pre>
 * 
 * 
 */
@XmlAccessorType(XmlAccessType.FIELD)
@XmlType(name = "createCryptoToken", propOrder = {
   "arg0",
   "arg1",
   "arg2",
   "arg3",
   "arg4",
})

public class CreateCryptoToken {

   protected String arg0;
   protected String arg1;
   protected String arg2;
   protected boolean arg3;
   protected List<String> arg4;
   
   /**
    * Gets the value of the arg0 property.
    * 
    */
   public String getArg0() {
       return arg0;
   }
 
   /**
    * Sets the value of the arg0 property.
    * 
    */
   public void setArg0(String value) {
       this.arg0 = value;
   }

   /**
    * Gets the value of the arg1 property.
    * 
    */
   public String getArg1() {
       return arg1;
   }

   /**
    * Sets the value of the arg1 property.
    * 
    */
   public void setArg1(String value) {
       this.arg1 = value;
   }
   
   /**
    * Gets the value of the arg2 property.
    * 
    */
   public String getArg2() {
       return arg2;
   }

   /**
    * Sets the value of the arg2 property.
    * 
    */
   public void setArg2(String value) {
       this.arg2 = value;
   }

   /**
    * Gets the value of the arg3 property.
    * 
    */
   public boolean getArg3() {
       return arg3;
   }

   /**
    * Sets the value of the arg3 property.
    * 
    */
   public void setArg3(boolean value) {
       this.arg3 = value;
   }

   /**
    * Gets the value of the arg4 property.
    * 
    * <p>
    * This accessor method returns a reference to the live list,
    * not a snapshot. Therefore any modification you make to the
    * returned list will be present inside the JAXB object.
    * This is why there is not a <CODE>set</CODE> method for the arg1 property.
    * 
    * <p>
    * For example, to add a new item, do as follows:
    * <pre>
    *    getArg4().add(newItem);
    * </pre>
    * 
    * 
    * <p>
    * Objects of the following type(s) are allowed in the list
    * {@link String }
    * 
    * 
    */
   public List<String> getArg4() {
       if (arg4 == null) {
           arg4 = new ArrayList<String>();
       }
       return this.arg4;
   }

}