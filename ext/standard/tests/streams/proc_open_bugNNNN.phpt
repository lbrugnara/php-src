--TEST--
Bug #NNNN blocking_pipes = false hangs forever on Windows
--SKIPIF--
<?php
	if (substr(PHP_OS, 0, 3) != 'WIN') {
		die("Windows only");
	}

	if (getenv("SKIP_SLOW_TESTS")) {
		die("skip slow test");
	}
?>
--FILE--
<?php

// We keep track of stdout output to know when to break (see below)
$stdout = "";

// Parent's chunk size to read from STDOUT
$chunk_size = 1024;
// We want the child script to write to STDOUT "$chunk_size < $how_much < $chunk_size * 2 - 1" bytes
// that way the parent reads the first chunk, and after that it iterates one more time hanging on the
// fread (check the break conditions below to understand)
$how_much = rand($chunk_size, $chunk_size * 2 - 1);

// We will measure the last "non-blocking" read (the one that will contain less than $chunk_size bytes)
$start = 0;
$end = 0;
$elapsed = 0;

// Create the child script
$child_script = str_replace(".php", ".", __FILE__) . "child.php";

$written = file_put_contents($child_script, "<?php
\$how_much = $how_much;

\$data0 = str_repeat('a', \$how_much);
fwrite(STDOUT, \$data0);

// Wait for something to keep alive the process
fgets(STDIN);
");

if (!$written) {
	die("couldn't create child process script '$child_script'");
}

$cmd = PHP_BINARY . " -n $child_script";
$pipes = [];
$descriptors = [ 
	0 => [ "pipe", "rb" ],  // stdin
	1 => [ "pipe", "wb" ]  	// stdout
];

// To trigger the infinite loop we need to set blocking_pipes to false (Windows only)
$process = proc_open($cmd, $descriptors, $pipes, null, null, [ 'blocking_pipes' => false ]);

if (!is_resource($process)) {
	die("Couldn't start the child process");
}

do {
	// We want to measure only the latest read, so it is ok to do it this way
	$start = microtime(true);
	$read = fread($pipes[1], $chunk_size);
	$end = microtime(true);
	$elapsed = $end - $start;

	// 1) Break if we already consumed output and the last read was empty
	if (!isset($read[0]) && isset($stdout[0]))
		break;

	$stdout .= $read;
	
	// 2) Break if we read a chunk of bytes smaller than our chunk size
	if (isset($read[0]) && strlen($read) < $chunk_size)
		break;

	usleep(100000);
} while (true);

fclose($pipes[1]);

// Send something ending in PHP_EOL to make the child script stop
fwrite($pipes[0], "exit" . PHP_EOL);
fclose($pipes[0]);

proc_close($process);

// At this point, elapsed time is expected to be ~32 seconds (plain_wrapper.c:php_stdiop_read)
if ($elapsed > 31.0) {
	echo "Non-blocking read lasted {$elapsed} seconds" . PHP_EOL;
}

unlink($child_script);

exit(0);
?>
--CLEAN--
<?php
$child_script = str_replace(".clean.php", ".", __FILE__) . "child.php";
unlink($child_script);
?>
--EXPECTF--
Non-blocking read lasted %f seconds