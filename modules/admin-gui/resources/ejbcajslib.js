/*************************************************************************
 *                                                                       *
 *  EJBCA: The OpenSource Certificate Authority                          *
 *                                                                       *
 *  This software is free software; you can redistribute it and/or       *
 *  modify it under the terms of the GNU Lesser General Public           *
 *  License as published by the Free Software Foundation; either         *
 *  version 2.1 of the License, or any later version.                    *
 *                                                                       *
 *  See terms of license at gnu.org.                                     *
 *                                                                       *
 *************************************************************************/

/*
 * JavaScript library used by EJBCA JSP pages
 * First version 2002-03-27
 */

function checkAll(checkboxlist,size) {
  for (var i = 0; i < size; i++) {
    box = eval(checkboxlist + i  ); 
    if (box.checked == false)
      box.checked = true;
  }
}

function checkFieldNotEmpty(thetextfield, alerttext) {
	field = eval(thetextfield);
	var text = new String(field.value);
	if (!text || 0 === text.length || text === "") {
		alert(alerttext)
		return false
	}
	return true;
}

/**
 * Used in importca.xhtml and importcacert.xhtml
 * 
 * @param message the message to be printed in case no file is selected to import
 * @returns false if no file selected for import, true otherwise
 */
function checkFileRecieve(element, message) {
	if (document.getElementById(element).value == '') {
		alert(message);
		return false;
	}
	return true;
}

/**
 * Used in managecas.xhtml
 * 
 * @param message the message to be shown to user before confirming the delete operation
 * @returns false in case message is null or empty, otherwise returns a delete confirmation dialogue to user.
 */
function confirmcaaction(message) {
    if (!message || 0 === message.length) {
        return false;
    }
    return confirm(message);
}

function checkcreatecafield(thetextfield, alerttext) {
	checkFieldNotEmpty(thetextfield, "Please give a ca name first!");
	return checkfieldforlegalchars(thetextfield, alerttext);
}

/**
 * Used in editcapage.xhtml
 * 
 * @param link
 *            The link to the certificate to be shown
 * 
 */
function viewcacert(link){
    win_popup = window.open(link, 'view_cert','height=750,width=750,scrollbars=yes,toolbar=no,resizable=1');
    win_popup.focus();
}

function uncheckAll(checkboxlist,size) {
  for (var i = 0; i < size; i++) {
  box = eval(checkboxlist + i ); 
  if (box.checked == true) 
    box.checked = false;
  }
}

function switchAll(checkboxlist,size) {
  for (var i = 0; i < size; i++) {
    box = eval(checkboxlist+ i);
    box.checked = !box.checked;
  }
}

// Function that checks thru an array of checkboxes an return true if only one is checked,
// if several is checked the alerttext is displayed, if none is selected then only false is returned.
function onlyoneselected(checkboxlist,size,alerttext){
  var numberofchecked=0;
  for(var i = 0; i < size; i++){
    box = eval(checkboxlist + i);   
    if (box.checked == true){
      numberofchecked++;
    }  
  }

  if(numberofchecked > 1){
    alert(alerttext);
  }

  return (numberofchecked==1);
}

function checkfieldforlegalchars(thetextfield , alerttext){
  field = eval(thetextfield);
  var text = new String(field.value);
  
  re = /[^\u0041-\u005a\u0061-\u007a\u00a1-\ud7ff\ue000-\uffff_ 0-9@\.\*\,\-:\/\?\'\=\(\)\|.]/g; 

  if(re.exec(text)){
    alert(alerttext);
    return false;
  }
  else{
    return true;
  }
}

function checkfieldforlegalcharswithchangeable(thetextfield , alerttext){
  field = eval(thetextfield);
  var text = new String(field.value);
  re = /[^\u0041-\u005a\u0061-\u007a\u00a1-\ud7ff\ue000-\uffff_ 0-9@\.\-;]/g;
  if(re.exec(text)){
    alert(alerttext);
    return false;
  }
  else{
    return true;
  }
}

function checkfieldforlegaldnchars(thetextfield , alerttext){
  field = eval(thetextfield);
  var text = new String(field.value);
  re = /[^\u0041-\u005a\u0061-\u007a\u00a1-\ud7ff\ue000-\uffff_ 0-9@\.\&\*\,\\\-:\/\?\'\=\#\(\)\|\+]/g;
  if(re.exec(text)){
    alert(alerttext);
    return false;
  }
  else{
    return true;
  }
}

function checkfieldforcompletednchars(thetextfield , alerttext){
  field = eval(thetextfield);
  var text = new String(field.value);
  re = /[^\u0041-\u005a\u0061-\u007a\u00a1-\ud7ff\ue000-\uffff_ 0-9@\,\=\.\*\-:\/\?\'\#\(\)\|\\]/g;
  if(re.exec(text)){
    alert(alerttext);
    return false;
  }
  else{
    return true;
  }
}

function checkfieldforlegaldncharswithchangeable(thetextfield , alerttext){
  field = eval(thetextfield);
  var text = new String(field.value);
  re = /[^\u0041-\u005a\u0061-\u007a\u00a1-\ud7ff\ue000-\uffff_ 0-9@\.\,\*\-:\/;\'\?\+\=\#\(\)\|\"]/g;
  if(re.exec(text)){
    alert(alerttext);
    return false;
  }
  else{
    return true;
  }
}

function checkfieldforipaddess(thetextfield , alerttext){
  field = eval(thetextfield);
  var text = new String(field.value);
  // 0-9, A-F, a-f, ., :
  re = /[^\u0030-\u0039\u0041-\u0046\u0061-\u0066\.\:]/g;
  if(re.exec(text)){
    alert(alerttext);
    return false;
  }
  else{
    return true;
  }
}

function checkfieldforlegalemailchars(thetextfield , alerttext){
  field = eval(thetextfield);
  var text = new String(field.value);
  re = /[^\u0041-\u005a\u0061-\u007a\u00a1-\ud7ff\ue000-\uffff_0-9@\.\-\']/g;
  if(re.exec(text)){
    alert(alerttext);
    return false;
  }
  else{
    return true;
  }
}

function checkfieldforlegalemailcharswithchangeable(thetextfield , alerttext){
  field = eval(thetextfield);
  var text = new String(field.value);
  re = /[^\u0041-\u005a\u0061-\u007a\u00a1-\ud7ff\ue000-\uffff_0-9@\.\-;]/g;
  if(re.exec(text)){
    alert(alerttext);
    return false;
  }
  else{
    return true;
  }
}

function checkfieldforlegalemailcharswithoutat(thetextfield , alerttext){
  field = eval(thetextfield);
  var text = new String(field.value);
  text = text.trim();
  re = /[^\u0041-\u005a\u0061-\u007a\u00a1-\ud7ff\ue000-\uffff_0-9\.\-\']/g;
  if(re.exec(text)){
    alert(alerttext);
    return false;
  }
  else{
    return true;
  }
}

function checkfieldforlegalemailcharswithoutatwithchangeable(thetextfield , alerttext){
  field = eval(thetextfield);
  var text = new String(field.value);
  text = text.trim();
  re = /[^\u0041-\u005a\u0061-\u007a\u00a1-\ud7ff\ue000-\uffff_0-9\.\-;]/g;
  if(re.exec(text)){
    alert(alerttext);
    return false;
  }
  else{
    return true;
  }
}


function checkfieldfordecimalnumbers(thetextfield , alerttext){
  field = eval(thetextfield);
  var text = new String(field.value);
  re = /[^0-9]/g;
  if(re.exec(text)){
    alert(alerttext);
    return false;
  }
  else{
    return true;
  }
}

function checkfieldforgender(thetextfield, alerttext) {
  field = eval(thetextfield);
  var text = new String(field.value);
  re = /[^MmFf]/g;
  if(re.exec(text)){
    alert(alerttext);
    return false;  
  }
  else{
  	return true;
  }	
  
}

/** Verify that the field is of format '*y *mo *d' with optional sequence and formulas (+-) accepted. */
function checkFieldForCrlSimpleTime(thetextfield, alerttext) {
  field = eval(thetextfield);
  var text = new String(field.value);
  re = /\s*(([+-]?\d+)\s*([m][o]|[y]|[d]|[h]|[m]))\s*/ig;
  tokens = text.match(re);
  if (null != tokens && tokens.length > 0 && tokens.join("").valueOf() == text.valueOf()) {
	  var result = 0;
	  for (i=0;i<tokens.length;i++) {
	    if (tokens[i].toLowerCase().indexOf('mo') > 0) {
			result=result+parseInt(tokens[i])*30*24*60*60*1000;
		}
		if (tokens[i].toLowerCase().indexOf('y') > 0) {
			result=result+parseInt(tokens[i])*365*24*60*60*1000;
		}
		if (tokens[i].toLowerCase().indexOf('d') > 0) {
		    result=result+parseInt(tokens[i])*24*60*60*1000;
		}
		if (tokens[i].toLowerCase().indexOf('h') > 0) {
		    result=result+parseInt(tokens[i])*60*60*1000;
		}
		if (tokens[i].toLowerCase().indexOf('m') > 0) {
		    result=result+parseInt(tokens[i])*60*1000;
		}
	  }
	  if (result > -1) {
		return true;
	  }
  }
  alert(alerttext);
  return false;
}

/** Verify that the field is of format '*y *mo *d' or decimal */
function checkFieldForYearsMonthsDays(thetextfield , alerttext) {
  field = eval(thetextfield);
  var text = new String(field.value);
  re = /^\s*((\d+\s*[yY])?\s*(\d+\s*[mM][oO])?\s*(\d+\s*[dD])?)\s*$|^\s*[0-9]+\s*$/;
  if (re.exec(text)) {
	  return true;
  }
  alert(alerttext);
  return false;
}

/** Verify that the field is of format 'YYYYMMDD' */
function checkFieldForDate(thetextfield, alerttext) {
	field = eval(thetextfield);
	var text = new String(field.value);
	re = /(19|20)[0-9]{2}(0[1-9]|1[012])(0[1-9]|[12][0-9]|3[01])/;
	if ( (text.length > 0) && ((!re.exec(text) || (text.length != 8))) ) {
		alert(alerttext);
		return false;
	}
	else {
		return true;
	}
}

function checkfieldforhexadecimalnumbers(thetextfield , alerttext){
  // remove all spaces
  field = eval(thetextfield);
  var text = new String(field.value);  
  re = /[^a-fA-F0-9 ]/g;
  if(re.exec(text)){
    alert(alerttext);
    return false;
  }
  else{
    return true;
  }
}

function checkfieldforlegalresourcechars(thetextfield , alerttext){
  field = eval(thetextfield);
  var text = new String(field.value);
  re = /[^\u0041-\u005a\u0061-\u007a\u00a1-\ud7ff\ue000-\uffff_ 0-9\/]/g;
  if(re.exec(text)){
    alert(alerttext);
    return false;
  }
  else{
    return true;
  }
}

function trim(s) {
  while (s.substring(0,1) == ' ') {
    s = s.substring(1,s.length);
  }
  while (s.substring(s.length-1,s.length) == ' ') {
    s = s.substring(0,s.length-1);
  }
  return s;
}

function inputIntoField(oldaliasfield, aliasfield, oldalias, infotext) {
	var input = prompt(infotext,"");
	if (input != null && "" != input) {
		document.getElementById(oldaliasfield).value = oldalias;
		document.getElementById(aliasfield).value = input;
		return true;
	}
	document.getElementById(oldaliasfield).value = '';
	document.getElementById(aliasfield).value = '';
	return false;
}

function inputIntoFieldConfirm(confirmmessage, field, input) {
	var confirmed = confirm(confirmmessage);
	if (confirmed && input != null && "" != input) {
		document.getElementById(field).value = input;
		return true;
	}
	document.getElementById(field).value = '';
	return false;
}

function logout() {
	// Redirects user to RA web (through LogOutServlet) and terminates session.
	var logoutUrl = "https://" + window.location.hostname + ":" + window.location.port + "/ejbca/adminweb/logout";
	window.location.href = logoutUrl;
}

// Resets timer for page inactivity.
// parameter 'validity' should be specified in minutes.
function resetTimer(validity) {
	clearTimeout(time);
	// Log out after X minutes of inactivity
	time=setTimeout(logout, 1000*60*validity)
}

/* JS library functions used by EJBCA 6.8.0+ JSF pages */
(function() {
    "use strict";

    /** Scroll the element with elementId into view on AJAX requests success. */
    var onAjaxSuccessScrollTo = function(data, elementId) {
        if (data.status == "success") {
        	var y = 0;
        	if (elementId) {
            	var element = document.getElementById(elementId);
            	while (element && !isNaN(element.offsetTop) ) {
            		y += element.offsetTop - element.scrollTop;
            		element = element.offsetParent;
            	}
        	}
        	//console.log("Scrolling element '" + elementId + "' into view using coordinates (0, " + y + ").");
        	window.scroll(0, y);
        }
    };

    /** Shows or hides all cells by class name of the element inside it (this is needed since <h:column> cannot be part of <f:ajax> updates) */
    var hideShowCellsByClass = function(className, show) {
        var cells = document.getElementsByClassName(className);
        for (var i = 0; i < cells.length; i++) {
            cells[i].parentNode.style.display = show ? 'table-cell' : 'none';
        }
    };

    // Setup name space...
    window.ejbca = window.ejbca || {};
    ejbca.adminweb = ejbca.adminweb || {};
    // ...and expose API functions under this name space.
    ejbca.adminweb.onAjaxSuccessScrollTo = onAjaxSuccessScrollTo;
    ejbca.adminweb.hideShowCellsByClass = hideShowCellsByClass;
}());
