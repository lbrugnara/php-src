<?php

if (!function_exists('pcntl_fork')) {
	require_once "servernofork.inc";
} else {
	require_once "serverfork.inc";
}
?>
