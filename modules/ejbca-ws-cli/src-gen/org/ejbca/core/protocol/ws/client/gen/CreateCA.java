package org.ejbca.core.protocol.ws.client.gen;

import java.util.HashMap;

import javax.xml.bind.annotation.XmlAccessType;
import javax.xml.bind.annotation.XmlAccessorType;
import javax.xml.bind.annotation.XmlType;

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
 *         &lt;element name="arg3" type="{http://www.w3.org/2001/XMLSchema}String"/>
 *         &lt;element name="arg4" type="{http://www.w3.org/2001/XMLSchema}String"/>
 *         &lt;element name="arg5" type="{http://www.w3.org/2001/XMLSchema}HashMap"/>
 *         &lt;element name="arg6" type="{http://www.w3.org/2001/XMLSchema}String"/>
 *         &lt;element name="arg7" type="{http://www.w3.org/2001/XMLSchema}String"/>
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
   "arg10",
   "arg11",
   "arg12",
})

public class CreateCA {

   protected String arg0;
   protected String arg1;
   protected String arg2;
   protected String arg3;
   protected String arg4;
   protected HashMap<Object, Object> arg5;
   protected String arg6;
   protected String arg7;
   protected long arg8;
   protected String arg9;
   protected String arg10;
   protected String arg11;
   protected int arg12;
   
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
   public String getArg3() {
       return arg3;
   }

   /**
    * Sets the value of the arg3 property.
    * 
    */
   public void setArg3(String value) {
       this.arg3 = value;
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
   public HashMap<Object, Object> getArg5() {
       return arg5;
   }

   /**
    * Sets the value of the arg5 property.
    * 
    */
   public void setArg5(HashMap<Object, Object> value) {
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
   public long getArg8() {
       return arg8;
   }

   /**
    * Sets the value of the arg8 property.
    * 
    */
   public void setArg8(long value) {
       this.arg8 = value;
   }
   
   /**
    * Gets the value of the arg9 property.
    * 
    */
   public String getArg9() {
       return arg9;
   }

   /**
    * Sets the value of the arg9 property.
    * 
    */
   public void setArg9(String value) {
       this.arg9 = value;
   }
   
   /**
    * Gets the value of the arg10 property.
    * 
    */
   public String getArg10() {
       return arg10;
   }

   /**
    * Sets the value of the arg10 property.
    * 
    */
   public void setArg10(String value) {
       this.arg10 = value;
   }
   
   /**
    * Gets the value of the arg11 property.
    * 
    */
   public String getArg11() {
       return arg11;
   }

   /**
    * Sets the value of the arg11 property.
    * 
    */
   public void setArg11(String value) {
       this.arg11 = value;
   }
   
   /**
    * Gets the value of the arg12 property.
    * 
    */
   public int getArg12() {
       return arg12;
   }

   /**
    * Sets the value of the arg12 property.
    * 
    */
   public void setArg12(int value) {
       this.arg12 = value;
   }

}