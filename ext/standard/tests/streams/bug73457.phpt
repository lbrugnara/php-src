--TEST--
Bug #73457. Wrong error message when fopen FTP wrapped fails to open data connection
--SKIPIF--
<?php
if (array_search('ftp',stream_get_wrappers()) === FALSE) die("skip ftp wrapper not available.");
?>
--FILE--
<?php

$bug73457=true;
require __DIR__ . "/../../../ftp/tests/server.inc";

$path="ftp://127.0.0.1:" . $port."/bug73457";

$ds=file_get_contents($path);
var_dump($ds);
?>
==DONE==
--EXPECTREGEX--
Warning: file_get_contents\(ftp:\/\/127\.0\.0\.1:[0-9]+\/bug73457\): failed to open stream: Failed to set up data channel: (Connection refused in .+ on line [0-9]+|No connection could be made because the target machine actively refused it\.)\n?.*\nbool\(false\)
==DONE==
