--TEST--
stream_set_blocking call should return true on valid pipes returned by proc_open
--FILE--
<?php

$ls = substr(PHP_OS, 0, 3) != 'WIN' ? "dir" : "ls";
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

fclose($pipes[0]);
fclose($pipes[1]);
fclose($pipes[2]);

proc_close($proc);

?>
--EXPECT--
bool(true)
bool(true)
bool(true)
bool(true)
bool(true)
bool(true)