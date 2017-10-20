<?php

function mb_str_split( $string ) {
    # Split at all position not after the start: ^
    # and not before the end: $
    return preg_split('/(?<!^)(?!$)/u', $string );
}

mb_internal_encoding("UTF-8");

$vendorlen = 6; // the lower the value, the less memory it uses

$vendorlistURL = "https://code.wireshark.org/review/gitweb?p=wireshark.git;a=blob_plain;f=manuf";

$ouicontent = file_get_contents($vendorlistURL);

$ouilines = explode("\n", $ouicontent);

$uniqvendors = array();
$vendorbymac = array();
$total = 0;
$totalvendorlen = 0;
$uniq = 0;

/* preparing arrays: extract vendor names and mac addresses */

foreach($ouilines as $line) {
  if(trim($line)=='') continue; // skip empty lines
  if(substr(trim($line), 0, 1)=='#') continue; // skip comments
  $parts = explode("\t", $line); // separated by tabs
  if(count($parts)<3) continue; // need 3 rows
  $mac = trim($parts[0]);
  if(strlen($mac)!=8) continue; // discard invalid or too long mac fragments
  
  $vendorname = trim($parts[1]);
  $vendorname = str_replace(" ", "", $vendorname);
  
  if(mb_strlen($vendorname)>$vendorlen) { // like mb_substr()
    $chars = mb_str_split($vendorname);
    while( strlen( implode("", $chars) ) > $vendorlen ) {
      array_pop($chars);
    }
    $vendorname = implode("", $chars);
  }

  if(mb_strlen($vendorname)<$vendorlen) { // fill to 6 chars
    $vendorname = $vendorname.str_repeat(" ", $vendorlen-mb_strlen($vendorname));
  }

  if(!isset($uniqvendors[$vendorname])) {
    $uniqvendors[$vendorname] = array(
      'index' => $uniq,
      'amount' => 0,
      'longname' => trim($parts[1])
     );
    $uniq++;
  } else {
    $uniqvendors[$vendorname]['amount']++;
  }
  $totalvendorlen += strlen($vendorname); // a bit useless since everything is formatted to 6 chars
  $vendorbymac[$mac] = $vendorname;
  
  if(mb_strlen($vendorname)!=$vendorlen || trim($vendorname)=='') {
    die(" !!!!!! Vendorname Error: $mac\t [".strlen($vendorname)."] $vendorname\n");
  }
  $total++;
}


/* build unique char list from unique vendor list */

$uniqchars = array( );
$total = 0;
$uniq = 0;
$maxstrlen = 0;
$charindex = 0;

foreach($uniqvendors as $vendor => $meta) {
  $chars = mb_str_split($vendor);
  $charindex = $charindex + count($chars);

  foreach($chars as $char) {
    if(!isset($uniqchars[$char])) {
      $uniqchars[$char] = $uniq;
      $uniq++;
      if(strlen($char)>$maxstrlen) $maxstrlen = strlen($char);
    }
    $total++;
  }
}



/* build mac list output, attach vendor idx */

$macvendorstr = "";
foreach($vendorbymac as $mac => $vendor) {
  $msblsb = sprintf("%04X", $uniqvendors[$vendor]['index']); // vendor idx is two bytes
  $hexbytes = str_split($msblsb, 2); // split them
  $macparts = explode(":", $mac);
  $macvendorstr .= "  0x".implode(", 0x", $macparts).", /* ".$vendor." */ 0x".$hexbytes[0].", 0x".$hexbytes[1].",\n";
}
$macvendorstr = substr($macvendorstr, 0, -2);



/* build alphabet glossary output */

$charindexstr = "";
$wrap = 0;
$num = 20;
$indexedchars = array();

foreach($uniqchars as $char => $id) {
  $indexedchars[$id] = $char;
  if($wrap++%$num==0) {
    $charindexstr.= "\n  ";
  }
  $charindexstr .=  '{"'.$char.'"}, ';
}
$charindexstr = substr($charindexstr, 0, -2);



/* vendors glossary convert char indexes to 7-bit as binary strings */

$binvendorstr = "";
$count = 0;
foreach($uniqvendors as $vendor => $meta) {
  $chars = mb_str_split($vendor);
  foreach($chars as $char) {
    if(!isset($uniqchars[$char])) {
      die(" !!!!! Untracked char on $vendor / '$char' (chr ".ord($char).") / '".$uniqchars[' ']."'\n"); 
    } else {
      $binvendorstr .= sprintf('%07b', $uniqchars[$char]);
    }
  }
}



/* vendors glossary encode 7-bit binary as 8-bit hex */

$octets = str_split($binvendorstr, 8);
$wrap = 0;
$num = 12;
$glossarystr = "";
foreach($octets as $octet) {
  if($wrap++%$num==0) {
    $glossarystr.= "\n  ";
  }
  $decoct = bindec($octet);
  $glossarystr.= sprintf('0x%02X', $decoct).", ";
}
$glossarystr = substr($glossarystr, 0, -2);



/* generate the C code */

$out = "#ifndef oui_h
#define oui_h

#define vendorBinBufSize ".($vendorlen*8+1)."
#define vendorNameSize $vendorlen
const int NUMBER_OF_VENDOR_NAMES = ".($uniq+1).";
const int MAX_MB_SIZE = ".($maxstrlen+1).";

char glossary [NUMBER_OF_VENDOR_NAMES] [MAX_MB_SIZE] = {
$charindexstr
};

const static uint8_t data_vendors[] PROGMEM = {
  /* mac1, mac2, mac3, glossaryidx1, glossaryidx2 */ 
$macvendorstr
};

const static uint8_t data_vendorglossary[".(count($octets))."] PROGMEM = {
$glossarystr
};
#endif
";


file_put_contents("../esp8266_deauther/oui7bits.h", $out);

echo " **** Unique vendor names: ".count($uniqvendors)." / Total mac addresses $total\n";
echo " **** CHARS: ".implode("", array_keys($uniqchars))."\n";
echo " **** SAVED oui7bits.h\n";

