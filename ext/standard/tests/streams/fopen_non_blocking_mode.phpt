--TEST--
fopen with 'n' in the mode parameter creates a non-blocking stream
--FILE--
<?php

$child_file = str_replace(".php", ".", __FILE__) . "child.php";

// The child will fopen the php://stdin stream with the 'n' argument to request non-blocking
// access to the stream
file_put_contents($child_file, 
'<?php

$stdinfd = fopen("php://stdin", "rbn");

$output = [
	"description" => "",
	"message" => ""
];

$reads = 0;
do {
	$reads++;

	$msg = fread($stdinfd, 1024);

	if ($msg === false)
		break;

	if (isset($msg[0]))
	{
		$output["description"] = ($reads === 1
			? "Read operation blocked on STDIN" 
			: "Read operation succeed after {$reads} non-blocking reads on STDIN") . PHP_EOL;
		$output["message"] = "Message content: " . $msg . PHP_EOL;
		break;
	}

	usleep(10000);
} while (true);

fwrite(STDOUT, $output["description"]);
fwrite(STDOUT, $output["message"]);

exit(0);

?>
');

$cmd = sprintf("%s -n %s", PHP_BINARY, $child_file);

$desc = [ 0 => [ "pipe", "r" ], 1 => ["pipe", "w"] ];

$proc = proc_open($cmd, $desc, $pipes);

if (!is_resource($proc)) 
	die("Couldn't run command");

// Make the child wait a little before writing to its STDIN
sleep(1);

fwrite($pipes[0], "from parent process");
fclose($pipes[0]);

// Wait for the 2 messages ending in PHP_EOL
echo fgets($pipes[1]);
echo fgets($pipes[1]);
fclose($pipes[1]);

proc_close($proc);

?>
--CLEAN--
<?php
$child_file = str_replace(".clean.php", ".", __FILE__) . "child.php";
unlink($child_file);
?>
--EXPECTF--
Read operation succeed after %d non-blocking reads on STDIN
Message content: from parent process