<?php

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
  if(strlen($mac)!=8) continue; // F8:02:78
  $vendorname = trim($parts[1]);
  $vendorname = str_replace(" ", "", $vendorname);
  if(strlen($vendorname)>$vendorlen) {
    $vendorname = mb_substr($vendorname, 0, $vendorlen);
  }

  if(strlen($vendorname)<$vendorlen) {
    $vendorname = $vendorname.str_repeat(" ", $vendorlen-strlen($vendorname));
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

  echo "$mac\t [".strlen($vendorname)."] $vendorname\t$vendorlongname\n";
  $total++;
}

echo "Unique vendors ".count($uniqvendors)." / Total vendord $total\n";
echo "Total vendor len: $totalvendorlen / Unique vendor len: ".strlen(implode("", array_keys($uniqvendors)))."\n";



/* build unique char list from unique vendor list */

$uniqchars = array();
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
      echo "[".$char."=".ord($char)."] ";
      if(strlen($char)>$maxstrlen) $maxstrlen = strlen($char);
    } else {
      //$uniqchars[$char]++;
    }
    $total++;
  }
}
echo "\n";

echo "Unique chars ".count($uniqchars)." / Total chars $total\n";
if(isset($uniqchars[" "])) {
  echo "Empty chars ".$uniqchars[" "]."\n";
} else {
  echo "No empty chars\n";
}


/* build mac list output, attach vendor idx */

$macvendorstr = "
const static uint8_t data_vendors[] PROGMEM = {
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
  echo $macstr."\n";
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


foreach($uniqchars as $char => $id) {
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

foreach($uniqvendors as $vendor => $meta) {
  $chars = mb_str_split($vendor);
  foreach($chars as $char) {
    $binvendorstr .= sprintf('%07b', $uniqchars[$char]);
  }
}

$octets = str_split($binvendorstr, 8);

echo "last : ".end($octets)."\n";

$wrap = 0;
$num = 9;
$lines = 0;


$out = "#ifndef oui_h
#define oui_h

$charindexstr

$macvendorstr


const static uint8_t data_vendorglossary[] PROGMEM = {

  ";


/* vendors glossary encode 7-bit binary as 8-bit hex */

foreach($octets as $octet) {
  if($wrap++%$num==0) {
    $lines++;
    $out.= "\n  ";
  }
  $out.= sprintf('0x%02X', bindec($octet)).", ";
}

$out = substr($out, 0, -2);
$out .= "
};
#endif
";

file_put_contents("oui7bits.h", $out);


echo "\n";
echo "$lines lines\n";

function mb_str_split( $string ) {
    # Split at all position not after the start: ^
    # and not before the end: $
    return preg_split('/(?<!^)(?!$)/u', $string );
}


exit(0);









/*


const static uint8_t data_vendors[] PROGMEM = {
"""

    for line in data:
        line = line.decode()

        # Skipping empty lines and comments
        if line.startswith('#') or line.startswith('\n'):
            continue

        mac, short_desc, *rest = line.strip().split('\t')

        # Limiting short_desc to 8 chars
        short_desc = short_desc[0:6]

        # Convert to ascii
        short_desc = short_desc.encode("ascii", "ignore").decode()

        mac_octects = len(mac.split(':'))
        if mac_octects == 6:
            continue
        else:
            # Convert to esp8266_deauther format
            short_desc = short_desc.ljust(6, '\0')
            hex_sdesc = ", 0x".join("{:02x}".format(ord(c)) for c in short_desc)

            (oc1, oc2, oc3) = mac.split(':')

            out = out + ("  0x{}, 0x{}, 0x{}, 0x{},\n".format(oc1.upper(), oc2.upper(), oc3.upper(),
                                                              hex_sdesc.upper().replace('X', 'x')))

    out = out[:-2] # Removing last comma
    out = out + "\n};\n#endif"

    # Saving to file
    if filename:
        with open(filename, 'w') as out_file:
            out_file.write("%s" % out)
    else:
        print(out)

if __name__ == "__main__":
    options = parse_options()
    generate_oui_h(options.url, options.output)


*/
