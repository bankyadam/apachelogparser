#!/usr/bin/php
<?php
include 'ApacheLogParser.php';

$format = '%h %l %u %t "%r" %>s %b "%{Referer}i" "%{User-agent}i"';
$line = '127.0.0.1 - frank [10/Oct/2000:13:55:36 -0700] "GET /apache_pb.gif HTTP/1.0" 200 2326 "http://www.example.com/start.html" "Mozilla/4.08 [en] (Win98; I ;Nav)"';

$logParser = new ApacheLogParser($format);
$result = $logParser->parseLine($line);
var_dump($result);
