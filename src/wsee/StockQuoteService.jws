/*
 * Copyright 2001,2004 The Apache Software Foundation.
 * 
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 * 
 *      http://www.apache.org/licenses/LICENSE-2.0
 * 
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

import org.apache.axis.utils.XMLUtils;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.NodeList;

/**
 * See \samples\stock\readme for info.
 *
 * @author Sanjiva Weerawarana (sanjiva@watson.ibm.com)
 * @author Doug Davis (dug@us.ibm.com)
 */
public class StockQuoteService {
  public float getQuote (String symbol) throws Exception {
    // get a real (delayed by 20min) stockquote from 
    // http://www.xmltoday.com/examples/stockquote/. The IP addr 
    // below came from the host that the above form posts to ..

    if ( symbol.equals("XXX") ) return( (float) 66.25 );


    Document doc = null ;
    
    doc = XMLUtils.newDocument( "http://www.xmltoday.com/examples/" +
                                "stockquote/getxmlquote.vep?s="+symbol );

    Element  elem = doc.getDocumentElement();
    NodeList list = elem.getElementsByTagName("stock_quote");

    elem = (Element) list.item(0);
    list = elem.getElementsByTagName( "price" );
    elem = (Element) list.item( 0 );
    String quoteStr = elem.getAttribute("value");
    try {
      return Float.valueOf(quoteStr).floatValue();
    } catch (NumberFormatException e1) {
      // maybe its an int?
      try {
        return Integer.valueOf(quoteStr).intValue() * 1.0F;
      } catch (NumberFormatException e2) {
        return -1.0F;
      }
    }
  }
}
