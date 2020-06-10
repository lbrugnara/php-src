--TEST--
stream_set_blocking should succeed pipes returned by proc_open
--FILE--
<?php

$ls = strstr(PHP_OS, "WIN") !== false ? "dir" : "ls";
$cmd = sprintf("%s", $ls);

$desc = [ 0 => ["pipe", "r"], 1 => ["pipe", "w"], 2 => ["pipe", "w"] ];

$proc = proc_open($cmd, $desc, $pipes);

if (!is_resource($proc)) 
	die("Couldn't run command");

var_dump(stream_set_blocking($pipes[0], false));
var_dump(stream_set_blocking($pipes[1], false));
var_dump(stream_set_blocking($pipes[2], false));

var_dump(stream_set_blocking($pipes[0], true));
var_dump(stream_set_blocking($pipes[1], true));
var_dump(stream_set_blocking($pipes[2], true));
	
proc_close($proc);

?>
--EXPECTF--
bool(true)
bool(true)
bool(true)
bool(true)
bool(true)
bool(true)