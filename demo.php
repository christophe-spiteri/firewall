<?php

use ClsScript\Firewall;

include_once('Firewall.php');
$userAgent         = ['python-'];
$excludeUrl        = [
    '/server',
    '/.git',
    '/adminer.php',
    '/wp-',
    '/app',
    '/console',
    '/blog',
    '/joomla',
    '/wordpress',
];
$refererBlackList  = ['binance.com', 'anonymousfox.co'];
$hostNameWhiteList = ['googlebot.com', 'google.com', 'search.msn.com'];
$whiteListIp       = [];
Firewall::init($userAgent, $excludeUrl, $refererBlackList, $hostNameWhiteList, $whiteListIp);
Firewall::test(true);
Firewall::run();

die('passage');