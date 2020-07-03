--TEST--
stat() on directory should return 40755 for ftp://
--SKIPIF--
<?php
if (array_search('ftp',stream_get_wrappers()) === FALSE) die("skip ftp wrapper not available.");
?>
--FILE--
<?php

require __DIR__ . "/../../../ftp/tests/server.inc";

$path = "ftp://localhost:" . $port."/www";

if (substr(PHP_OS, 0, 3) === 'WIN') {
    echo 'Windows: ';
}
var_dump(stat($path)['mode']);
?>
==DONE==
--EXPECTREGEX--
string\(11\) "SIZE \/www\n"\n(int\(16877\)|Windows: int\(16868\))
==DONE==
