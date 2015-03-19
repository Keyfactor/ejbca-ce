package org.ejbca.core.protocol.ws.client.gen;

import java.util.ArrayList;
import java.util.List;

import javax.xml.bind.annotation.XmlAccessType;
import javax.xml.bind.annotation.XmlAccessorType;
import javax.xml.bind.annotation.XmlType;

import org.ejbca.util.KeyValuePair;

/**
 * <p>Java class for createCA complex type.
 * 
 * <p>The following schema fragment specifies the expected content contained within this class.
 * 
 * <pre>
 * &lt;complexType name="createCA">
 *   &lt;complexContent>
 *     &lt;restriction base="{http://www.w3.org/2001/XMLSchema}anyType">
 *       &lt;sequence>
 *         &lt;element name="arg0" type="{http://www.w3.org/2001/XMLSchema}String"/>
 *         &lt;element name="arg1" type="{http://www.w3.org/2001/XMLSchema}String"/>
 *         &lt;element name="arg2" type="{http://www.w3.org/2001/XMLSchema}String"/>
 *         &lt;element name="arg5" type="{http://www.w3.org/2001/XMLSchema}KeyValuePair" maxOccurs="unbounded" minOccurs="0"/>
 *         &lt;element name="arg6" type="{http://www.w3.org/2001/XMLSchema}String"/>
 *         &lt;element name="arg8" type="{http://www.w3.org/2001/XMLSchema}long"/>
 *         &lt;element name="arg9" type="{http://www.w3.org/2001/XMLSchema}String"/>
 *         &lt;element name="arg10" type="{http://www.w3.org/2001/XMLSchema}String"/>
 *         &lt;element name="arg11" type="{http://www.w3.org/2001/XMLSchema}String"/>
 *         &lt;element name="arg12" type="{http://www.w3.org/2001/XMLSchema}int"/>
 *       &lt;/sequence>
 *     &lt;/restriction>
 *   &lt;/complexContent>
 * &lt;/complexType>
 * </pre>
 * 
 * 
 */
@XmlAccessorType(XmlAccessType.FIELD)
@XmlType(name = "createCA", propOrder = {
   "arg0",
   "arg1",
   "arg2",
   "arg3",
   "arg4",
   "arg5",
   "arg6",
   "arg7",
   "arg8",
   "arg9",
})

public class CreateCA {

   protected String arg0;
   protected String arg1;
   protected String arg2;
   protected List<KeyValuePair> arg3;
   protected String arg4;
   protected long arg5;
   protected String arg6;
   protected String arg7;
   protected String arg8;
   protected int arg9;
   
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
    * Gets the value of the arg5 property.
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
    *    getArg3().add(newItem);
    * </pre>
    * 
    * 
    * <p>
    * Objects of the following type(s) are allowed in the list
    * {@link KeyValuePair }
    * 
    * 
    */
   public List<KeyValuePair> getArg3() {
       if (arg3 == null) {
           arg3 = new ArrayList<KeyValuePair>();
       }
       return this.arg3;
   }

   /**
    * Gets the value of the arg4 property.
    * 
    */
   public String getArg4() {
       return arg4;
   }

   /**
    * Sets the value of the arg4 property.
    * 
    */
   public void setArg4(String value) {
       this.arg4 = value;
   }

   /**
    * Gets the value of the arg5 property.
    * 
    */
   public long getArg5() {
       return arg5;
   }

   /**
    * Sets the value of the arg5 property.
    * 
    */
   public void setArg5(long value) {
       this.arg5 = value;
   }
   
   /**
    * Gets the value of the arg6 property.
    * 
    */
   public String getArg6() {
       return arg6;
   }

   /**
    * Sets the value of the arg6 property.
    * 
    */
   public void setArg6(String value) {
       this.arg6 = value;
   }
   
   /**
    * Gets the value of the arg7 property.
    * 
    */
   public String getArg7() {
       return arg7;
   }

   /**
    * Sets the value of the arg7 property.
    * 
    */
   public void setArg7(String value) {
       this.arg7 = value;
   }
   
   /**
    * Gets the value of the arg8 property.
    * 
    */
   public String getArg8() {
       return arg8;
   }

   /**
    * Sets the value of the arg8 property.
    * 
    */
   public void setArg8(String value) {
       this.arg8 = value;
   }
   
   /**
    * Gets the value of the arg9 property.
    * 
    */
   public int getArg9() {
       return arg9;
   }

   /**
    * Sets the value of the arg9 property.
    * 
    */
   public void setArg9(int value) {
       this.arg9 = value;
   }

}