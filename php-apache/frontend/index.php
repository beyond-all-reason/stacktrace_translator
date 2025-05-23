<?php

/*
	Simple Frontend for the Stacktrace translator on http://springrts.com:8000/
	Note: the file lastrun has to be writable by the webserver
*/


/*
	limits the usage of the script, only allow this script to be run every 10 seconds
*/
$lastrun=sys_get_temp_dir()."/.lastrun";

function limit(){
	global $lastrun;
	$stat=stat($lastrun);
	$diff=$stat['mtime'] + 0 - time();
	if ( $diff > 0 )
		die("Please wait $diff seconds to rerun this script");
	else
		touch($lastrun);
}

/**
	returns the spring version of the string in filecontents
*/
function getVersion($filecontents){
	$res=preg_match('/(Spring ([0-9]+.[0-9]+)(.\d*-\d*-g([0-9a-f]{7})\s)?(\w*)\s?(\((.*)\))?)(\n)/',$filecontents,$matches);
	if ($res==1) {
		$wholeVersion=$matches[1];
		$syncVersion=$matches[2];
		$commit=$matches[4];
		$branch=$matches[6];
		$buildFlags=$matches[8];
		return $wholeVersion;
	}
	return "";
}

/**
	returns the spring commit of the string in filecontents
*/
function getCommit($filecontents) {
	$res=preg_match('/(Spring ([0-9]+.[0-9]+)(.\d*-\d*-g([0-9a-f]{7})\s)?(\w*)\s?(\((.*)\))?)(\n)/',$filecontents,$matches);
	if ($res==1) {
		$wholeVersion=$matches[1];
		$syncVersion=$matches[2];
		$commit=$matches[4];
		$branch=$matches[6];
		$buildFlags=$matches[8];
		return $commit;
	}
	return "";
}

/**
	returns the spring branch of the string in filecontents
*/
function getBranch($filecontents) {
	$res=preg_match('/(Spring ([0-9]+.[0-9]+)(.\d*-\d*-g([0-9a-f]{7})\s)?(\w*)\s?(\((.*)\))?)(\n)/',$filecontents,$matches);
	if ($res==1) {
		$wholeVersion=$matches[1];
		$syncVersion=$matches[2];
		$commit=$matches[4];
		$branch=$matches[6];
		$buildFlags=$matches[8];
		return (!empty($branch)) ? $branch : "master";
	}
	return "develop";
}

/**
	returns true if url is valid http:// url
	has to return false if url is local file
*/
function isValidURL($url){
	return preg_match('|^http(s)?://[a-z0-9-]+(.[a-z0-9-]+)*(:[0-9]+)?(/.*)?$|i', $url);
}
/**
	posts to pastebin, returns url
*/
function pastebin($text, $name=""){
	/*
	$name=substr($name,strlen($name)-23); //limit name to 23 chars
	$request = http_build_query(array( 'paste_code' => $text,
		'name' => 'spring-stacktrace',
		'title' => $name,
		'private' => 1,
		'text' => $text,
	));
	$context = stream_context_create(array('http' => array(
		'method' => "POST",
		'header' => 'Content-type: application/x-www-form-urlencoded',
		'content' => $request)));
		$file = file_get_contents("http://paste.springfiles.com/api/create", false, $context);
		return $file;
	*/
}

/**
	does the translate_stacktrace request on $rpcserver and returns the decoded result
*/
function xmlrpcrequest($rpcserver, $infolog){
	$request = xmlrpc_encode_request("translate_stacktrace", $infolog);

	#$header[] = "Host: springrts.com";
	$header[] = "Content-type: text/xml";

	$curl=curl_init();
	curl_setopt( $curl, CURLOPT_URL, $rpcserver);
	curl_setopt( $curl, CURLOPT_RETURNTRANSFER, 1 );
	curl_setopt( $curl, CURLOPT_HTTPHEADER, $header );
	curl_setopt( $curl, CURLOPT_CUSTOMREQUEST, 'POST' );
	curl_setopt( $curl, CURLOPT_FAILONERROR, 1);
	curl_setopt( $curl, CURLOPT_POSTFIELDS, $request );

	$file=curl_exec($curl);
	$err=curl_error($curl);
	if ($file===false)
		die($rpcserver.":".$err);
	curl_close($curl);
	$res=xmlrpc_decode($file);
	return $res;
}

/**
	fetches infolog.txt and normalize it
*/
function getinfolog(){
	global $_REQUEST;
	if(array_key_exists('url',$_REQUEST)){
		$url=$_REQUEST['url'];
	}else
		$url="";
	if($url!=""){ //url parameter unset
		if (!isValidURL($url)){
			die("Invalid url!");
		}
		$infolog=file_get_contents($url,false, NULL, -1, 1000000); //retrieve remote infolog.txt
	}else{
		if (array_key_exists('request',$_REQUEST))
			$infolog=$_REQUEST['request'];
		else
			return "";
	}
	$infolog=addslashes($infolog);
	$infolog=str_replace("\r\n","\n",$infolog); //windows linebreaks f'up some things here...
	$infolog=str_replace("\n\n","\n",$infolog);
	return stripslashes($infolog);
}

function parse_template($tpl, $vars){
	$file=file_get_contents($tpl);
	while(list($name,$value)=each($vars)){
		$file=str_replace("%".$name."%",$value,$file);
	}
	return $file;
}
/**
	parses the result of an xmlrequest and returns a string ready for html output
*/
function parse_result($res,$ver,$commit,$branch){
	$pastebin="";
	$name="";
	$textwithlinks="";
	if (array_key_exists('faultString',$res)){
		$cleantext= "Error: ".$res['faultString']."<br>\n";
		$cleantext.= "Maybe this stacktrace is from an self-compiled spring, or is the stack-trace to old?\n";
		$cleantext.= "This script only can handle >=0.82\n";
	}else{
		$textwithlinks="<h1>translated with links to github source ('$ver' detected)</h1>\n";
		$textwithlinks.="<table><tr><td>module</td><td>address</td><td>file</td><td>line</td></tr>\n";
		$cleantext="";
		for($i=0;$i<count($res); $i++){
			$module = $res[$i][0];
			$address = $res[$i][1];
			$filename = $res[$i][2];
			$line = $res[$i][3];
			if (!empty($filename)) {
				$regres=preg_match('/.*(rts\/.*)/', $filename, $matches);
				if ($regres==1 && !empty($matches[1])) {
					$filename=$matches[1];
				}
			}
			if ($name=="")
				$name=$filename.":".$line;
			$textwithlinks.="<tr>\n";
			$textwithlinks.= "<td>".$module . "</td><td> " . $address . "</td><td> " . $filename . "</td>\n";
			$cleantext.= $module." ".$address." ".$filename.":".$line."\n";

			if (!empty($filename) && ($filename[0]=='r')){
				if (!empty($commit)){
					$textwithlinks.='<td><a target="_blank" href="https://github.com/beyond-all-reason/spring/blob/BAR105/'.$filename.'#L'.$line.'">'.$line.'</a></td>';
				} else {
					// $textwithlinks.='<td><a target="_blank" href="http://github.com/beyond-all-reason/spring/tree/BAR105/'.$filename.'#L'.$line.'">'.$line.'</a></td>';
					$textwithlinks.='<td><a target="_blank" href="https://github.com/beyond-all-reason/RecoilEngine/tree/master/'.$filename.'#L'.$line.'">'.$line.'</a></td>';
				}
			}else {
				$textwithlinks.="<td>$line</td>";
			}
			$textwithlinks.= "</tr>\n";
		}
		$textwithlinks.= "</table>\n";
	}
	if (($cleantext!="")&&(isset($_REQUEST['pastebin']))){
		$url=pastebin($cleantext,$name);
		$pastebin="Pastebin url: <a href=\"$url\" target=\"_blank\">$url</a>";
	}
	$cleantext = "<h1>translated for copy and paste</h1>\n<pre>$cleantext</pre>";

	return array( 'PASTEBIN' => $pastebin,
			'RESULTCLEAN' => $cleantext,
			'RESULTHTML' =>	$textwithlinks );
}
$res['PASTEBIN']=""; /*initianlize vars for template*/
$res['RESULTHTML']="";
$res['RESULTCLEAN']="";
$res['TEXTAREA']=getinfolog();
#$res['TRANSLATOR']="http://imolarpg.dyndns.org:8000";
$res['TRANSLATOR']="http://python-server:8000";
$res['INFO']="";

if ($res['TEXTAREA']!=""){
	limit();
	$tmp=xmlrpcrequest($res['TRANSLATOR'],$res['TEXTAREA']);
/*	if (array_key_exists('faultString',$tmp)){
		$res['INFO']="<h1>Warning: using local translator, as remote can't translate</h1>";
		$res['TRANSLATOR']="http://abma.de:8000";
		$tmp=xmlrpcrequest($res['TRANSLATOR'],$res['TEXTAREA']);
	}*/
	$res=array_merge($res,parse_result($tmp,getVersion($res['TEXTAREA']),getCommit($res['TEXTAREA']),getBranch($res['TEXTAREA'])));
}
$res['ACTION']=$_SERVER['SCRIPT_NAME'];
echo parse_template("index.tpl",$res);

?>
