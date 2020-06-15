--TEST--
popen with 'n' in the mode parameter creates a non-blocking stream
--FILE--
<?php

$program = "sleep(1); fwrite(STDOUT, 'from STDOUT'); exit(0);";

$cmd = sprintf("%s -n -r \"%s\"", PHP_BINARY, $program);

$proc = popen($cmd, "rbn");

if (!is_resource($proc)) 
	die("Couldn't run command");

$output = [
    'description' => '',
    'message' => '',
];

$reads = 0;
do {
	$reads++;

	$outmsg = fread($proc, 1024);

	if ($outmsg === false)
		break;

	if (isset($outmsg[0]))
	{
		$output['description'] = ($reads === 1
			? "Read operation blocked on STDOUT pipe" 
			: "Read operation succeed after {$reads} non-blocking reads on STDOUT pipe") . PHP_EOL;
		$output['message'] = "Message content: " . $outmsg . PHP_EOL;
		break;
	}

	usleep(10000);
} while (true);

pclose($proc);

echo $output['description'];
echo $output['message'];

?>
--EXPECTF--
Read operation succeed after %d non-blocking reads on STDOUT pipe
Message content: from STDOUT