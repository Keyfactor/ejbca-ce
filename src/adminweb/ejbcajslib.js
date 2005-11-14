<!--
/* Javascript library used by Ejbca jsp pages
     Written by Philip Vendil 
     27 mars 2002 */



function checkAll(checkboxlist,size) {
  for (var i = 0; i < size; i++) {
    box = eval(checkboxlist + i  ); 
    if (box.checked == false)
      box.checked = true;
  }
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

function displayHelpWindow(helplink) {
  window.open(helplink, 'ejbca_helpwindow','height=600,width=500,scrollbars=yes,toolbar=yes,resizable=1');
}

function checkfieldforlegalchars(thetextfield , alerttext){
  field = eval(thetextfield);
  var text = new String(field.value);
  
  re = /[^\u0041-\u005a\u0061-\u007a\u00aa\u00b5\u00ba\u00c0-\u00d6\u00d8-\u00f6\u00f8-\u01ba\u01bc-\u01bf\u01c4-\u02ad\u0386\u0388-\u0481\u048c-\u0556\u0561-\u0587\u10a0-\u10c5\u1e00-\u1fbc\u1fbe\u1fc2-\u1fcc\u1fd0-\u1fdb\u1fe0-\u1fec\u1ff2-\u1ffc\u207f\u2102\u2107\u210a-\u2113\u2115\u2119-\u211d\u2124\u2126\u2128\u212a-\u212d\u212f-\u2131\u2133\u2134\u2139\ufb00-\ufb17\uff21-\uff3a\uff41-\uff5a_ 0-9\-]/g; 

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
  re = /[^\u0041-\u005a\u0061-\u007a\u00aa\u00b5\u00ba\u00c0-\u00d6\u00d8-\u00f6\u00f8-\u01ba\u01bc-\u01bf\u01c4-\u02ad\u0386\u0388-\u0481\u048c-\u0556\u0561-\u0587\u10a0-\u10c5\u1e00-\u1fbc\u1fbe\u1fc2-\u1fcc\u1fd0-\u1fdb\u1fe0-\u1fec\u1ff2-\u1ffc\u207f\u2102\u2107\u210a-\u2113\u2115\u2119-\u211d\u2124\u2126\u2128\u212a-\u212d\u212f-\u2131\u2133\u2134\u2139\ufb00-\ufb17\uff21-\uff3a\uff41-\uff5a_ 0-9\-;]/g;
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
  re = /[^\u0041-\u005a\u0061-\u007a\u00aa\u00b5\u00ba\u00c0-\u00d6\u00d8-\u00f6\u00f8-\u01ba\u01bc-\u01bf\u01c4-\u02ad\u0386\u0388-\u0481\u048c-\u0556\u0561-\u0587\u10a0-\u10c5\u1e00-\u1fbc\u1fbe\u1fc2-\u1fcc\u1fd0-\u1fdb\u1fe0-\u1fec\u1ff2-\u1ffc\u207f\u2102\u2107\u210a-\u2113\u2115\u2119-\u211d\u2124\u2126\u2128\u212a-\u212d\u212f-\u2131\u2133\u2134\u2139\ufb00-\ufb17\uff21-\uff3a\uff41-\uff5a@\.\*\,\-:\/\?\'\=\(\)]/g;
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
  re = /[^\u0041-\u005a\u0061-\u007a\u00aa\u00b5\u00ba\u00c0-\u00d6\u00d8-\u00f6\u00f8-\u01ba\u01bc-\u01bf\u01c4-\u02ad\u0386\u0388-\u0481\u048c-\u0556\u0561-\u0587\u10a0-\u10c5\u1e00-\u1fbc\u1fbe\u1fc2-\u1fcc\u1fd0-\u1fdb\u1fe0-\u1fec\u1ff2-\u1ffc\u207f\u2102\u2107\u210a-\u2113\u2115\u2119-\u211d\u2124\u2126\u2128\u212a-\u212d\u212f-\u2131\u2133\u2134\u2139\ufb00-\ufb17\uff21-\uff3a\uff41-\uff5a@\,\=\.\*\-:\/\?\'\(\)]/g;
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
  re = /[^\u0041-\u005a\u0061-\u007a\u00aa\u00b5\u00ba\u00c0-\u00d6\u00d8-\u00f6\u00f8-\u01ba\u01bc-\u01bf\u01c4-\u02ad\u0386\u0388-\u0481\u048c-\u0556\u0561-\u0587\u10a0-\u10c5\u1e00-\u1fbc\u1fbe\u1fc2-\u1fcc\u1fd0-\u1fdb\u1fe0-\u1fec\u1ff2-\u1ffc\u207f\u2102\u2107\u210a-\u2113\u2115\u2119-\u211d\u2124\u2126\u2128\u212a-\u212d\u212f-\u2131\u2133\u2134\u2139\ufb00-\ufb17\uff21-\uff3a\uff41-\uff5a@\.\,\*\-:\/;\'\?\+\=\(\)\"]/g;
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
  re = /[^0-9\.]/g;
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
  re = /[^\u0041-\u005a\u0061-\u007a\u00aa\u00b5\u00ba\u00c0-\u00d6\u00d8-\u00f6\u00f8-\u01ba\u01bc-\u01bf\u01c4-\u02ad\u0386\u0388-\u0481\u048c-\u0556\u0561-\u0587\u10a0-\u10c5\u1e00-\u1fbc\u1fbe\u1fc2-\u1fcc\u1fd0-\u1fdb\u1fe0-\u1fec\u1ff2-\u1ffc\u207f\u2102\u2107\u210a-\u2113\u2115\u2119-\u211d\u2124\u2126\u2128\u212a-\u212d\u212f-\u2131\u2133\u2134\u2139\ufb00-\ufb17\uff21-\uff3a\uff41-\uff5a_0-9@\.\-]/g;
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
  re = /[^\u0041-\u005a\u0061-\u007a\u00aa\u00b5\u00ba\u00c0-\u00d6\u00d8-\u00f6\u00f8-\u01ba\u01bc-\u01bf\u01c4-\u02ad\u0386\u0388-\u0481\u048c-\u0556\u0561-\u0587\u10a0-\u10c5\u1e00-\u1fbc\u1fbe\u1fc2-\u1fcc\u1fd0-\u1fdb\u1fe0-\u1fec\u1ff2-\u1ffc\u207f\u2102\u2107\u210a-\u2113\u2115\u2119-\u211d\u2124\u2126\u2128\u212a-\u212d\u212f-\u2131\u2133\u2134\u2139\ufb00-\ufb17\uff21-\uff3a\uff41-\uff5a_0-9@\.\-;]/g;
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
  re = /[^\u0041-\u005a\u0061-\u007a\u00aa\u00b5\u00ba\u00c0-\u00d6\u00d8-\u00f6\u00f8-\u01ba\u01bc-\u01bf\u01c4-\u02ad\u0386\u0388-\u0481\u048c-\u0556\u0561-\u0587\u10a0-\u10c5\u1e00-\u1fbc\u1fbe\u1fc2-\u1fcc\u1fd0-\u1fdb\u1fe0-\u1fec\u1ff2-\u1ffc\u207f\u2102\u2107\u210a-\u2113\u2115\u2119-\u211d\u2124\u2126\u2128\u212a-\u212d\u212f-\u2131\u2133\u2134\u2139\ufb00-\ufb17\uff21-\uff3a\uff41-\uff5a_0-9\.\-]/g;
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
  re = /[^\u0041-\u005a\u0061-\u007a\u00aa\u00b5\u00ba\u00c0-\u00d6\u00d8-\u00f6\u00f8-\u01ba\u01bc-\u01bf\u01c4-\u02ad\u0386\u0388-\u0481\u048c-\u0556\u0561-\u0587\u10a0-\u10c5\u1e00-\u1fbc\u1fbe\u1fc2-\u1fcc\u1fd0-\u1fdb\u1fe0-\u1fec\u1ff2-\u1ffc\u207f\u2102\u2107\u210a-\u2113\u2115\u2119-\u211d\u2124\u2126\u2128\u212a-\u212d\u212f-\u2131\u2133\u2134\u2139\ufb00-\ufb17\uff21-\uff3a\uff41-\uff5a_0-9\.\-;]/g;
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
  re = /[^\u0041-\u005a\u0061-\u007a\u00aa\u00b5\u00ba\u00c0-\u00d6\u00d8-\u00f6\u00f8-\u01ba\u01bc-\u01bf\u01c4-\u02ad\u0386\u0388-\u0481\u048c-\u0556\u0561-\u0587\u10a0-\u10c5\u1e00-\u1fbc\u1fbe\u1fc2-\u1fcc\u1fd0-\u1fdb\u1fe0-\u1fec\u1ff2-\u1ffc\u207f\u2102\u2107\u210a-\u2113\u2115\u2119-\u211d\u2124\u2126\u2128\u212a-\u212d\u212f-\u2131\u2133\u2134\u2139\ufb00-\ufb17\uff21-\uff3a\uff41-\uff5a_ 0-9\/]/g;
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
-->