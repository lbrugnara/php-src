--TEST--
A non-blocking read within a loop should try many times until read output from the child's pipe
--FILE--
<?php

$child_file = str_replace(".php", ".", __FILE__) . "child.php";

file_put_contents($child_file, 
"<?php
sleep(1);
fwrite(STDOUT, 'From STDOUT');
sleep(1);
fwrite(STDERR, 'From STDERR');
exit(0);"
);

$cmd = sprintf("%s -n %s", PHP_BINARY, $child_file);

$desc = [ 1 => ["pipe", "w"], 2 => ["pipe", "w"] ];

$proc = proc_open($cmd, $desc, $pipes);

if (!is_resource($proc)) 
	die("Couldn't run command");

stream_set_blocking($pipes[1], false);
stream_set_blocking($pipes[2], false);

$output = [
	1 => [
		'description' => '',
		'message' => '',
	],
	2 => [
		'description' => '',
		'message' => '',
	]
];

$reads = 0;
do {
	$reads++;

	$outmsg = fread($pipes[1], 1024);

	if ($outmsg === false)
		break;

	if (isset($outmsg[0]))
	{
		$output[1]['description'] = ($reads === 1
			? "Read operation blocked on pipe 1" 
			: "Read operation succeed after {$reads} non-blocking reads on pipe 1") . PHP_EOL;
		$output[1]['message'] = "Message content: " . $outmsg . PHP_EOL;
		break;
	}

	usleep(10000);
} while (true);

$reads = 0;
do {
	$reads++;

	$errmsg = fread($pipes[2], 1024);

	if ($errmsg === false)
		break;

	if (isset($errmsg[0]))
	{
		$output[2]['description'] = ($reads === 1
			? "Read operation blocked on pipe 2" 
			: "Read operation succeed after {$reads} non-blocking reads on pipe 2") . PHP_EOL;
		$output[2]['message'] = "Message content: " . $errmsg . PHP_EOL;
		break;
	}

	usleep(10000);
} while (true);

proc_close($proc);

echo $output[1]['description'];
echo $output[1]['message'];
echo $output[2]['description'];
echo $output[2]['message'];

?>
--CLEAN--
<?php
$child_file = str_replace(".clean.php", ".", __FILE__) . "child.php";
unlink($child_file);
?>
--EXPECTF--
Read operation succeed after %d non-blocking reads on pipe 1
Message content: From STDOUT
Read operation succeed after %d non-blocking reads on pipe 2
Message content: From STDERR