<?php

echo "\n\n";

mb_internal_encoding("UTF-8");

$vendorlen = 6;


$vendorlistURL = "manuf";//"https://code.wireshark.org/review/gitweb?p=wireshark.git;a=blob_plain;f=manuf"

$ouicontent = file_get_contents($vendorlistURL);

$ouilines = explode("\n", $ouicontent);

$uniqvendors = array();
$vendorbymac = array();
$total = 0;
$totalvendorlen = 0;
$uniq = 0;

/* preparing arrays: extract vendor names and mac addresses */

foreach($ouilines as $line) {
  if(trim($line)=='') continue;
  if(substr(trim($line), 0, 1)=='#') continue;
  $parts = explode("\t", $line);
  if(count($parts)<3) continue;
  $mac = trim($parts[0]);
  if(strlen($mac)!=8) continue; 
  $vendorname = iconv('UTF-8', 'ASCII//IGNORE', trim($parts[1]));
  $vendorname = str_replace(" ", "", $vendorname);
  
  if(strlen($vendorname)>$vendorlen) {
    $chars = mb_str_split($vendorname);
    while( strlen( implode("", $chars) ) > $vendorlen ) {
      array_pop($chars);
    }
    $vendorname = implode("", $chars); //mb_substr($vendorname, 0, $vendorlen);
  }

  if(strlen($vendorname)<$vendorlen) {
    $vendorname = $vendorname.str_repeat("~", $vendorlen-strlen($vendorname));
  }

  if(!isset($uniqvendors[$vendorname])) {
    $uniqvendors[$vendorname] = array(
      'index' => $uniq,
      'position' => '',
      'amount' => 0
     );
    $uniq++;
  } else {
    $uniqvendors[$vendorname]['amount']++;
  }
  $totalvendorlen+= strlen($vendorname); // a bit useless since everything is formatted to 6 chars
  $vendorlongname = trim($parts[2]);

  $vendorbymac[$mac] = $vendorname;
  
  if(strlen($vendorname)!=6 || trim($vendorname)=='') {
    echo " !!!!!! Error: $mac\t [".strlen($vendorname)."] $vendorname\t$vendorlongname\n";
  }
  
  $total++;
}

echo " **** Unique vendors ".count($uniqvendors)." / Total mac addresses $total\n";
echo " **** Total vendor len: $totalvendorlen / Unique vendor strlen: ".strlen(implode("", array_keys($uniqvendors)))."\n";

//exit(0);

/* build unique char list from unique vendor list */

$uniqchars = array( );
$total = 0;
$uniq = 0;
$maxstrlen = 0;
$charindex = 0;

foreach($uniqvendors as $vendor => $meta) {
  $chars = mb_str_split($vendor);
  $uniqvendors[$vendor]['position'] = $charindex;
  $charindex = $charindex + count($chars);

  foreach($chars as $char) {
    if(!isset($uniqchars[$char])) {
      $uniqchars[$char] = $uniq;
      $uniq++;
      // echo "[".$char."=".ord($char)."] ";
      if(strlen($char)>$maxstrlen) $maxstrlen = strlen($char);
    } else {
      //$uniqchars[$char]++;
    }
    $total++;
  }
}

echo " **** Unique chars ".count($uniqchars)." / Total chars in vendorlist $total\n";
echo " **** CHARS: ".implode("", array_keys($uniqchars))."\n";

if(isset($uniqchars[" "])) {
  echo " **** Found [space] chars \n";
} else {
  echo " **** No [space] chars found\n";
}

//exit(0);


/* build mac list output, attach vendor idx */

$macvendorstr = "
const static uint8_t data_macaddresses[] PROGMEM = {
  /* mac1, mac2, mac3, glossaryidx1, glossaryidx2 */ 

";

foreach($vendorbymac as $mac => $vendor) {
  //$len = mb_strlen($vendor);
  $len = $uniqvendors[$vendor]['index'];
  $macparts = explode(":", $mac);
  $indhex = sprintf("%04X", $len); // vendor idx is two bytes
  $hexbytes = str_split($indhex, 2); // split them
  $macstr = "  0x".implode(", 0x", $macparts).", /* $vendor */ 0x".$hexbytes[0].", 0x".$hexbytes[1].", ";
  $macvendorstr .= $macstr."\n";
  //echo $macstr."\n";
}


$macvendorstr = substr($macvendorstr, 0, -2);

$macvendorstr .= "
};
";



/* build alphabet glossary output */


$charindexstr = "
const int NUMBER_OF_VENDOR_NAMES = ".($uniq+1).";
const int MAX_MB_SIZE = ".($maxstrlen+1).";

char glossary [NUMBER_OF_VENDOR_NAMES] [MAX_MB_SIZE] = {
  ";

$wrap = 0;
$num = 20;
$lines = 0;
$indexedchars = array();

foreach($uniqchars as $char => $id) {
  $indexedchars[$id] = $char;
  if($wrap++%$num==0) {
    $lines++;
    $charindexstr.= "\n  ";
  }
  $charindexstr .=  '{"'.$char.'"}, ';
}

$charindexstr = substr($charindexstr, 0, -2);

$charindexstr .= "\n};\n";

//die($charindexstr);




/* vendors glossary convert char indexes to 7-bit as binary strings */

$binvendorstr = "";
//$allchars = array_keys($uniqchars);
//echo array_search("M", $allchars);
$count = 0;

foreach($uniqvendors as $vendor => $meta) {
  $chars = mb_str_split($vendor);
  
  if(count($chars)!=6) echo "WTF on $vendor / ".count($char)." \n"; 
  
  foreach($chars as $char) {
    if(!isset($uniqchars[$char])) {
      echo "WTF on $vendor / '$char' (chr ".ord($char).") / '".$uniqchars[' ']."'\n"; 
    } else {
      $binvendorstr .= sprintf('%07b', $uniqchars[$char]);/*$uniqchars[$char]*/
    }
  }
  
  if($count++>1540 && $count < 1640) echo $vendor."\n";
  
}


echo " **** CRC success for bin vendor str len : ".strlen($binvendorstr)." (".(strlen($binvendorstr)/(7*6))." = ".count($uniqvendors).")\n";

$octets = str_split($binvendorstr, 8);

echo " ** Last byte: &b".end($octets)."\n";

$wrap = 0;
$num = 12;
$lines = 0;


$out = "#ifndef oui_h
#define oui_h

$charindexstr

$macvendorstr


const static uint8_t data_vendorglossary[".(count($octets))."] PROGMEM = {

  ";


/* vendors glossary encode 7-bit binary as 8-bit hex */

$octvendors = array();


foreach($octets as $octet) {
  if($wrap++%$num==0) {
    $lines++;
    $out.= "\n  ";
  }
  $decoct = bindec($octet);
  if($decoct>255) die("DOH ".$octet);
  $out.= sprintf('0x%02X', $decoct).", ";
  $octvendors[] = $decoct;
}

$out = substr($out, 0, -2);
$out .= "
};
#endif
";

file_put_contents("../esp8266_deauther/oui7bits.h", $out);


echo " **** SAVED oui7bits.h\n";


echo " ************ now rebuilding data locally ***************** \n";

/****
   DEBUG, rebuild testing
****/

$indexed_vendorlist = implode("\n", array_keys($uniqvendors));

file_put_contents("indexed_vendorlist", $indexed_vendorlist);

$septets = str_split($binvendorstr, 7);

$outverify = "";
$outvcount = 1;

foreach($septets as $septet) {
  $outverify.= $indexedchars[bindec($septet)];
  if($outvcount%6==0) {
    $outverify.= "\n";
  }
  $outvcount++;
}

$outverify = trim($outverify);

file_put_contents("rebuilt_vendorlist", $outverify);

if($indexed_vendorlist!=$outverify) {
  die("Invalid binary\n");
}


$octout = "";
$octcount = 0;
$maxindex = count($octvendors)-1;

foreach($octvendors as $index => $octvendor) {
  if($index == $maxindex) {
    $octbin8 = sprintf('%b', $octvendor);
    //if(strlen($octbin8)!=8) die("duh at $octcount : $octbin8 ".strlen($octout)." ".$octvendor);
    echo "Last octvendor len ($octbin8) : ".strlen($octbin8)."\n";
  } else {
    $octbin8 = sprintf('%08b', $octvendor);
  }
  $octout .= $octbin8;

  //$octcount++;
}

//exit(0);

$octout7bit = str_split($octout, 7);

$outverify = "";
$outvcount = 1;

foreach($octout7bit as $septet) {
  $outverify.= $indexedchars[bindec($septet)];
  if($outvcount%6==0) {
    $outverify.= "\n";
  }
  $outvcount++;
}

$outverify = trim($outverify);

file_put_contents("rebuilt_binvendorlist", $outverify);

if($indexed_vendorlist!=$outverify) {
  die("Decoded Invalid binary\n");
} else {
  echo "Indexed vendorlist decoded okay !";
}


function mb_str_split( $string ) {
    # Split at all position not after the start: ^
    # and not before the end: $
    return preg_split('/(?<!^)(?!$)/u', $string );
}

