package se.anatom.ejbca.hardtoken.hardtokenprofiles;


import java.awt.image.BufferedImage;
import java.awt.image.RenderedImage;
import java.awt.print.Printable;
import java.awt.print.PrinterException;
import java.io.ByteArrayOutputStream;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.Reader;
import java.text.DateFormat;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Date;
import java.util.Iterator;
import java.util.regex.Pattern;

import javax.imageio.ImageIO;

import org.apache.batik.dom.GenericText;
import org.apache.batik.dom.svg.SAXSVGDocumentFactory;
import org.apache.batik.dom.svg.SVGDOMImplementation;
import org.apache.batik.dom.svg.SVGOMDocument;
import org.apache.batik.dom.svg.SVGOMImageElement;
import org.apache.batik.dom.svg.SVGOMTSpanElement;
import org.apache.batik.svggen.ImageHandlerBase64Encoder;
import org.apache.batik.svggen.SVGGeneratorContext;
import org.apache.batik.svggen.SimpleImageHandler;
import org.apache.batik.transcoder.TranscoderInput;
import org.apache.batik.transcoder.TranscoderOutput;
import org.apache.batik.transcoder.print.PrintTranscoder;
import org.apache.batik.util.XMLResourceDescriptor;
import org.w3c.dom.Document;
import org.w3c.dom.Node;
import org.w3c.dom.NodeList;
import org.w3c.dom.svg.SVGRectElement;
import org.w3c.dom.svg.SVGTextElement;



import se.anatom.ejbca.ra.UserAdminData;
import se.anatom.ejbca.ra.raadmin.DNFieldExtractor;


/**
 * This is a help class used to manipulate SVG images.
 * It replaces all occurrenses of specified variables in the images 
 * with the corresponding userdata.
 *
 * @version $Id: SVGImageManipulator.java,v 1.5 2004-02-02 11:55:27 herrvendil Exp $
 */
public class SVGImageManipulator {

	/**
     * Availabe vairables used to replace text in a printlayout
     * Variable text are case-insensitive.
     */
    private static final Pattern USERNAME = Pattern.compile("\\$USERNAME", Pattern.CASE_INSENSITIVE);    
    private static final Pattern CN       = Pattern.compile("\\$CN", Pattern.CASE_INSENSITIVE);
    private static final Pattern SN       = Pattern.compile("\\$SN", Pattern.CASE_INSENSITIVE);    
    private static final Pattern GIVENNAME= Pattern.compile("\\$GIVENNAME", Pattern.CASE_INSENSITIVE);
    private static final Pattern INITIALS = Pattern.compile("\\$INITIALS", Pattern.CASE_INSENSITIVE);
    private static final Pattern SURNAME = Pattern.compile("\\$SURNAME", Pattern.CASE_INSENSITIVE);
    private static final Pattern O        = Pattern.compile("\\$O", Pattern.CASE_INSENSITIVE);
    private static final Pattern OU       = Pattern.compile("\\$OU", Pattern.CASE_INSENSITIVE);
    private static final Pattern C        = Pattern.compile("\\$C", Pattern.CASE_INSENSITIVE);
    private static final Pattern LOCATION = Pattern.compile("\\$LOCATION", Pattern.CASE_INSENSITIVE);
	private static final Pattern TITLE    = Pattern.compile("\\$TITLE", Pattern.CASE_INSENSITIVE);
	
	/**
	 * Indicates the start date of the tokens validity.
	 */		
    private static final Pattern STARTDATE = Pattern.compile("\\$STARTDATE", Pattern.CASE_INSENSITIVE);
	/**
	 * Indicates the end date of the tokens validity.
	 */		
	private static final Pattern ENDDATE   = Pattern.compile("\\$ENDDATE", Pattern.CASE_INSENSITIVE);    
    
    private static final Pattern HARDTOKENSN = Pattern.compile("\\$HARDTOKENSN", Pattern.CASE_INSENSITIVE);

	private static final Pattern HARDTOKENSNWITHOUTPREFIX = Pattern.compile("\\$HARDTOKENSNWITHOUTPREFIX", Pattern.CASE_INSENSITIVE);

    /**
     * Constants used for pin and puk codes.     
     */
    
    private static final Pattern PIN1 = Pattern.compile("\\$PIN1", Pattern.CASE_INSENSITIVE);
	private static final Pattern PIN2 = Pattern.compile("\\$PIN2", Pattern.CASE_INSENSITIVE);
	private static final Pattern PIN3 = Pattern.compile("\\$PIN3", Pattern.CASE_INSENSITIVE);
	private static final Pattern PIN4 = Pattern.compile("\\$PIN4", Pattern.CASE_INSENSITIVE);
	private static final Pattern PIN5 = Pattern.compile("\\$PIN5", Pattern.CASE_INSENSITIVE);	

    private static final Pattern[] PINS = {PIN1, PIN2, PIN3, PIN4, PIN5};
        
	private static final Pattern PUK1 = Pattern.compile("\\$PUK1", Pattern.CASE_INSENSITIVE);
	private static final Pattern PUK2 = Pattern.compile("\\$PUK2", Pattern.CASE_INSENSITIVE);
	private static final Pattern PUK3 = Pattern.compile("\\$PUK3", Pattern.CASE_INSENSITIVE);
	private static final Pattern PUK4 = Pattern.compile("\\$PUK4", Pattern.CASE_INSENSITIVE);
	private static final Pattern PUK5 = Pattern.compile("\\$PUK5", Pattern.CASE_INSENSITIVE);	

	private static final Pattern[] PUKS = {PUK1, PUK2, PUK3, PUK4, PUK5};			
    /**
     *  Constants reserved for future use.
     */
	private static final Pattern CUSTOMTEXTROW1 = Pattern.compile("\\$CUSTOMTEXTROW1", Pattern.CASE_INSENSITIVE);      
	private static final Pattern CUSTOMTEXTROW2 = Pattern.compile("\\$CUSTOMTEXTROW2", Pattern.CASE_INSENSITIVE);
	private static final Pattern CUSTOMTEXTROW3 = Pattern.compile("\\$CUSTOMTEXTROW3", Pattern.CASE_INSENSITIVE);
	private static final Pattern CUSTOMTEXTROW4 = Pattern.compile("\\$CUSTOMTEXTROW4", Pattern.CASE_INSENSITIVE);
	private static final Pattern CUSTOMTEXTROW5 = Pattern.compile("\\$CUSTOMTEXTROW5", Pattern.CASE_INSENSITIVE);
	private static final Pattern COPYOFSN = Pattern.compile("\\$COPYOFSN", Pattern.CASE_INSENSITIVE);
	private static final Pattern COPYOFSNWITHOUTPREFIX = Pattern.compile("\\$COPYOFSNWITHOUTPREFIX", Pattern.CASE_INSENSITIVE);

    /**
     * Constructor for the SVGImageManipulator object
     * 
     * @param svgdata the xlm data to parse
     * @param validity the validity of the card i days.
     * @param hardtokensnprefix the prefix of all hard tokens generated with this profile.
     * @param imagex x-position for image, reserved for future use
     * @param imagey y-position for image, reserved for future use
     * @param imageheight heigth of image, reserved for future use
     * @param imagewidth width of image, reserved for future use
     * @param unit units used, reserved for future use
     * @throws IOException
     */
	
    public SVGImageManipulator(Reader svgdata, 
	                    int validity, 
						 String hardtokensnprefix) throws IOException {
      this.validityms = ( ((long)validity) * 1000 *  3600 * 24); // Validity i ms
      this.hardtokensnprefix = hardtokensnprefix;      

      String parser = XMLResourceDescriptor.getXMLParserClassName();
      SAXSVGDocumentFactory f = new SAXSVGDocumentFactory(parser);
      String svgNS = SVGDOMImplementation.SVG_NAMESPACE_URI;
      Document doc = f.createDocument(svgNS, svgdata);	 

      svgdoc = ((SVGOMDocument) doc); 	
    }	
	
    /**
     * Returns the message with userspecific data replaced.
     *
     *
     * @return A processed notification message.
     *     
     */
    public Printable print(UserAdminData userdata, 
                      String[] pincodes, String[] pukcodes,
	                  String hardtokensn, String copyoftokensn) throws IOException, PrinterException {
      // Initialize
	  DNFieldExtractor dnfields = new DNFieldExtractor(userdata.getDN(), DNFieldExtractor.TYPE_SUBJECTDN);
	  // DNFieldExtractor subaltnamefields = new DNFieldExtractor(dn,DNFieldExtractor.TYPE_SUBJECTALTNAME);
	  Date currenttime = new Date();
	  String startdate = DateFormat.getDateInstance(DateFormat.SHORT).format(currenttime);
	  
	  String enddate = DateFormat.getDateInstance(DateFormat.SHORT).format(new Date(currenttime.getTime() + (this.validityms)));
      String hardtokensnwithoutprefix = hardtokensn.substring(this.hardtokensnprefix.length());
      String copyoftokensnwithoutprefix = copyoftokensn.substring(this.hardtokensnprefix.length());


      // Clone document
      Node originaldokument = svgdoc.cloneNode(true);
      
      // Get Text rows
      Collection texts = new ArrayList();
	  NodeList list = svgdoc.getDocumentElement().getElementsByTagName("text");	  
	  int numberofelements = list.getLength();	  
	  for(int i=0; i<numberofelements; i++){
		Node node = list.item(i);		  
		if(node instanceof SVGTextElement){	
		  NodeList list2 = ((SVGTextElement) node).getChildNodes();
		  int numberofelements2 = list2.getLength();
		  for(int j=0;j<numberofelements2;j++){		  	  
			  Node node2 = list2.item(j);			  
			  if(node2 instanceof GenericText)
			  	texts.add(node2);			    
			  if(node2 instanceof SVGOMTSpanElement){
			  	 SVGOMTSpanElement tspan = (SVGOMTSpanElement) node2;
			  	 NodeList list3 = tspan.getChildNodes();
			  	 int numberofelements3 = list3.getLength();
			  	 for(int k=0;k<numberofelements3;k++){
			  	 	Node node3 = list3.item(k);
			  	 	if(node3 instanceof GenericText)
			  	 		texts.add(node3);			    
			  	 }
			  }		  
		  }
		}		  
	  }
	  
	  Iterator iter = texts.iterator();
	  String data = "";
	  while(iter.hasNext()){
	  	GenericText text = (GenericText) iter.next(); 
	  	data = text.getData();
	  	data = processString(data, userdata, dnfields, pincodes, pukcodes,
	  			hardtokensn, hardtokensnwithoutprefix,
				copyoftokensn, copyoftokensnwithoutprefix,
				startdate, enddate);			  
	  	text.setData(data);
	  }
                       
      // Add Image
      /**
      if(userdata.hasimage()){
        addImage(userdata);       
      } 
       */
	  insertImage(userdata); // special dravel for demo
      
      ByteArrayOutputStream baos = new ByteArrayOutputStream();     
      
      // Write it to stream.
      	  
	  PrintTranscoder t = new PrintTranscoder(); 
	  TranscoderInput input = new TranscoderInput(svgdoc);			  
	  TranscoderOutput output = new TranscoderOutput(baos);
		
	  // save the image
	 
	  t.transcode(input, output);

	  t.addTranscodingHint(PrintTranscoder. KEY_SCALE_TO_PAGE, new Boolean(false));
	         	  	  	   	 
      // Reuse original document
      svgdoc = (SVGOMDocument) originaldokument;
              
      return t;
    }

    

    private String processString(String text, UserAdminData userdata, DNFieldExtractor dnfields,
                                 String[] pincodes, String[] pukcodes, 
                                 String hardtokensn, String hardtokensnwithoutprefix,
                                 String copyoftokensn, String copyoftokensnwithoutprefix,
                                 String startdate, String enddate){
 
 
  	  text = USERNAME.matcher(text).replaceAll(userdata.getUsername());	  
      text = CN.matcher(text).replaceAll(dnfields.getField(DNFieldExtractor.CN, 0));
	  text = OU.matcher(text).replaceAll(dnfields.getField(DNFieldExtractor.OU, 0));
	  text = O.matcher(text).replaceAll(dnfields.getField(DNFieldExtractor.O, 0));
	  text = C.matcher(text).replaceAll(dnfields.getField(DNFieldExtractor.C, 0));
	  text = LOCATION.matcher(text).replaceAll(dnfields.getField(DNFieldExtractor.L, 0));
	  text = TITLE.matcher(text).replaceAll(dnfields.getField(DNFieldExtractor.T, 0));
      text = INITIALS.matcher(text).replaceAll(dnfields.getField(DNFieldExtractor.INITIALS, 0));       
      text = SN.matcher(text).replaceAll(dnfields.getField(DNFieldExtractor.SN, 0));
      text = SURNAME.matcher(text).replaceAll(dnfields.getField(DNFieldExtractor.SURNAME, 0));
      text = GIVENNAME.matcher(text).replaceAll(dnfields.getField(DNFieldExtractor.GIVENNAME, 0));

	  text = STARTDATE.matcher(text).replaceAll(startdate);			
	  text = ENDDATE.matcher(text).replaceAll(enddate);        
	  text = HARDTOKENSN.matcher(text).replaceAll(hardtokensn);
	  text = HARDTOKENSNWITHOUTPREFIX.matcher(text).replaceAll(hardtokensnwithoutprefix);

      for(int i=0; i<pincodes.length;i++){
      	text = PINS[i].matcher(text).replaceAll(pincodes[i]);
      }

	  for(int i=0; i<pukcodes.length;i++){
		text = PUKS[i].matcher(text).replaceAll(pukcodes[i]);
	  }

      //text = CUSTOMTEXTROW1.matcher(text).replaceAll(?);      
      //text = CUSTOMTEXTROW2.matcher(text).replaceAll(?);
      //text = CUSTOMTEXTROW3.matcher(text).replaceAll(?);
      //text = CUSTOMTEXTROW4.matcher(text).replaceAll(?);
      //text = CUSTOMTEXTROW5.matcher(text).replaceAll(?);
      //text = COPYOFSN.matcher(text).replaceAll(copyoftokensn);
      //text = COPYOFSNWITHOUTPREFIX.matcher(text).replaceAll(copyoftokensnwithoutprefix);

      	
      return text;	
    }


    // Private Methods
    private void insertImage(UserAdminData userdata) throws FileNotFoundException, IOException{
    	int imgx = 0;
    	int imgy = 0;
    	int imgwidth = 0;
    	int imgheight = 0;
    	
       String transform = null;
    	// Get image info from template
    	NodeList list = svgdoc.getDocumentElement().getElementsByTagName("rect");
    	int numberofelements = list.getLength();
    	for(int i=0; i<numberofelements; i++){
    		Node node = list.item(i);		  
    		if(node instanceof SVGRectElement){
    			SVGRectElement rectnode = (SVGRectElement) node;
                if(rectnode.getId().equalsIgnoreCase("USERPICTURE")){
                    transform = rectnode.getAttribute("transform");
                    imgx = (int) rectnode.getX().getBaseVal().getValue();
                    imgy = (int) rectnode.getY().getBaseVal().getValue();                    
                    imgwidth = (int) rectnode.getWidth().getBaseVal().getValue();
                    imgheight = (int) rectnode.getHeight().getBaseVal().getValue();
           
                }
    		 }
    	  }  
    	
    	if(imgwidth != 0 && imgheight != 0){    	
    	  // Special dravel for demo remove
		  BufferedImage image = ImageIO.read(new FileInputStream("c:\\userpicture.jpg"));
        // TODO get image.
      
      	
	      SVGOMImageElement imageelement = new SVGOMImageElement("", svgdoc); 
	      SimpleImageHandler imagehandler = new SimpleImageHandler(new ImageHandlerBase64Encoder());
		        				 		  
	      SVGGeneratorContext svgcxt = SVGGeneratorContext.createDefault(svgdoc);
            		        				 		  
	      imagehandler.handleImage((RenderedImage) image, imageelement,  
	                           imgx, imgy, 
	                           imgwidth, imgheight, 
	                           svgcxt);
          
          if(transform != null && !transform.equals(""))
            imageelement.setAttribute("transform", transform); 
           
	    svgdoc.getRootElement().appendChild(imageelement);
    	}
	    
    }

    // Private Variables
    private SVGOMDocument svgdoc;
    private long validityms;    
    private String hardtokensnprefix;    

    
}
