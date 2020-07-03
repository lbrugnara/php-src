<?php
if (!extension_loaded('ftp')) die('skip ftp extension not loaded');
if (!empty($ssl) && !extension_loaded('openssl')) die('skip openssl extension not loaded');
?>
