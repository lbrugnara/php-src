--TEST--
Bug #47918: stream_set_blocking() does not work with pipes opened with proc_open()
--SKIPIF--
<?php
if (substr(PHP_OS, 0, 3) != 'WIN') die('Only for Windows');
?>
--FILE--
<?php

// Define the descriptors.
$a_Descriptors = array(0 => array('pipe', 'r'), 1 => array('pipe', 'w'), 2 => array('pipe', 'w'));

// Provide a place for the pipes.
$a_Pipes = array();

// Create the thread.
$r_Thread = proc_open("dir c:\\ /b", $a_Descriptors, $a_Pipes, Null, $_ENV);

// Display the current STDOUT meta data.
echo "Blocked: " . (stream_get_meta_data($a_Pipes[1])['blocked'] ? "true" : "false") . PHP_EOL;

// Try to change the blocking mode to non-blocking.
echo (stream_set_blocking($a_Pipes[1], false) ? 'Successfully' : 'Failed to'), ' set blocking mode to non-blocking', PHP_EOL;

// Display the current STDOUT meta data.
echo "Blocked: " . (stream_get_meta_data($a_Pipes[1])['blocked'] ? "true" : "false") . PHP_EOL;
?>
--EXPECTF--
Blocked: true
Successfully set blocking mode to non-blocking
Blocked: false
