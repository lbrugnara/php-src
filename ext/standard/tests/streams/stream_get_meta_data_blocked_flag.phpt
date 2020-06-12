--TEST--
stream_get_meta_data should reflect the mode change in the pipe blocking state
--FILE--
<?php

$ls = substr(PHP_OS, 0, 3) != 'WIN' ? "dir" : "ls";
$cmd = sprintf("%s", $ls);

$desc = [ 0 => ["pipe", "r"], 1 => ["pipe", "w"], 2 => ["pipe", "w"] ];

$proc = proc_open($cmd, $desc, $pipes);

if (!is_resource($proc)) 
	die("Couldn't run command");

echo "Pipe 0 is in " . (stream_get_meta_data($pipes[0])['blocked'] ? 'blocking' : 'non-blocking') . " mode" . PHP_EOL;
stream_set_blocking($pipes[0], false);
echo "Pipe 0 is in " . (stream_get_meta_data($pipes[0])['blocked'] ? 'blocking' : 'non-blocking') . " mode" . PHP_EOL;

echo "Pipe 1 is in " . (stream_get_meta_data($pipes[1])['blocked'] ? 'blocking' : 'non-blocking') . " mode" . PHP_EOL;
stream_set_blocking($pipes[1], false);
echo "Pipe 1 is in " . (stream_get_meta_data($pipes[1])['blocked'] ? 'blocking' : 'non-blocking') . " mode" . PHP_EOL;

echo "Pipe 2 is in " . (stream_get_meta_data($pipes[2])['blocked'] ? 'blocking' : 'non-blocking') . " mode" . PHP_EOL;
stream_set_blocking($pipes[2], false);
echo "Pipe 2 is in " . (stream_get_meta_data($pipes[2])['blocked'] ? 'blocking' : 'non-blocking') . " mode" . PHP_EOL;

proc_close($proc);

?>
--EXPECT--
Pipe 0 is in blocking mode
Pipe 0 is in non-blocking mode
Pipe 1 is in blocking mode
Pipe 1 is in non-blocking mode
Pipe 2 is in blocking mode
Pipe 2 is in non-blocking mode