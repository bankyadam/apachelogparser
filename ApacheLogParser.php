<?php
/**
 * Apache Log Parser
 *
 * @author Adam Brunner <apachelogparser@gmail.com>
 * @copyright Copyright (c) 2009, Adam Brunner
 * @version 1.0-20090228
 * @package ApacheLogParser
 */
class ApacheLogParser
{
	/**
	 * @var array   Apache log elemek regularis kifejezesei. (Apache 2.2 kompatibilis)
	 * 
	 * @link http://httpd.apache.org/docs/2.2/mod/mod_log_config.html#formats
	 * 
	 * NOTE: Az ertekekben levo regularis kifejezesekben talalhato '#' karaktereket escape-elni kell!
	 */
	private static $pattern = array(
		// Remote IP-address
		'a' => '(?P<remoteIP>\d+\.\d+\.\d+\.\d+)',
		// Local IP-address
		'A' => '(?P<localIP>\d+\.\d+\.\d+\.\d+)',
		// Bytes sent, excluding HTTP headers
		'b' => '(?P<lengthCLF>(?:-|\d+))',
		// Bytes sent, excluding HTTP headers. In CLF format i.e. a '-' rather than a 0 when no bytes are sent
		'B' => '(?P<length>\d+)',
		// The contents of cookie Foobar in the request sent to the server
		'\{(?P<name>.+?)\}C' => '(?P<cookie___%NAME%>.+?)',
		// The time taken to serve the request, in microseconds
		'D' => '(?P<requestTimeMicro>\d+)',
		// The contents of the environment variable FOOBAR
		'\{(?P<name>[a-z-A-Z]+)\}e' => '(?P<env___%NAME%>.+?)',
		// Filename
		'f' => '(?P<filename>.+?)',
		// Remote host
		'h' => '(?P<host>\d+\.\d+\.\d+\.\d+)',
		// The request protocol
		'H' => '(?P<protocol>.+?)',
		// The contents of Foobar: header line(s) in the request sent to the server
		'\{(?P<name>[a-z-A-Z]+)\}i' => '(?P<reqHeader___%NAME%>.+?)',
		// Number of keepalive requests handled on this connection. Interesting if KeepAlive is being used, so that,
		// for example, a '1' means the first keepalive request after the initial one, '2' the second, etc...;
		// otherwise this is always 0 (indicating the initial request)
		'k' => '(?P<keepalive>\d+)',
		// Remote logname (from identd, if supplied)
		'l' => '(?P<logname>(?:-|\w+))',
		// The request method
		'm' => '(?P<method>GET|POST|HEAD|PUT|DELETE)',
		// The contents of note "Foobar" from another module
		'\{(?P<name>[a-zA-Z-]+)\}n' => '(?P<note___%NAME%>.+?)',
		// The contents of Foobar: header line(s) in the reply
		'\{(?P<name>[a-zA-Z-]+)\}o' => '(?P<respHeader___%NAME%>.+?)',
		// The canonical Port of the server serving the request
		'(?P<name>canonical|local|remote)?p' => '(?P<port___%NAME%>\d+)',
		// The process ID of the child that serviced the request
		'(?P<name>pid|tid|hextid|hexid)?P' => '(?P<pid___%NAME%>[a-fA-F\d]+)',
		// The query string (prepended with a ? if a query string exists, otherwise an empty string)
		'q' => '(?P<queryString>.*?)',
		// First line of request
		'r' => '(?P<request>(?:GET|POST|HEAD|PUT|DELETE) .+? HTTP/1.(?:0|1))',
		// Status.  For requests that got internally redirected, this is
		// the status of the *original* request --- %>s for the last
		's' => '(?P<status>\d{3})',
		// Time, in common log format time format (standard english format)
		't' => '\[(?P<time>\d{2}/(?:Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec)/\d{4}:\d{2}:\d{2}:\d{2} -?\d{4})\]',
		// The time, in the form given by format, which should be in strftime(3) format (potentially localized)
		'\{(?P<name>.+?)\}t' => '(?P<locTime___%NAME%>.+?)',
		// The time taken to serve the request, in seconds
		'T' => '(?P<requestTime>\d+)',
		// Remote user (from auth; may be bogus if return status (%s) is 401)
		'u' => '(?P<user>(?:-|\w+))',
		// The URL path requested, not including any query string
		'U' => '(?P<URL>.+?)',
		// The canonical ServerName of the server serving the request
		'v' => '(?P<serverName>.+?)',
		// The server name according to the UseCanonicalName setting
		'V' => '(?P<canonicalName>.+?)',
		// Connection status when response was completed
		//     'X' = connection aborted before the response completed
		//     '+' = connection may be kept alive after the response is sent
		//     '-' = connection will be closed after the response is sent
		'X' => '(?P<connectionStatus>X|+|-)',
		// Bytes received, including request and headers, cannot be zero
		'I' => '(?P<recBytes>\d+)',
		// Bytes sent, including headers, cannot be zero
		'O' => '(?P<sentBytes>\d+)',
	);
	
	/**
	 * @var string   A log sorainak formatumat tartalmazza.
	 */
	private $format = '';

	/**
	 * @var string   A feldolgozaskor hasznalt regularis kifejezes.
	 */
	private $parserExpression = '';
	
	/**
	 * Konstruktor
	 * 
	 * @param string   A log sorainak formatuma
	 * 
	 * @return void
	 */
	public function __construct($format)
	{
		$this->format = $format;
		$this->buildParserExpression();
	}

	/**
	 * Osszeallitja a megadott formatum alapjan a feldolgozashoz szukseges regularis kifejezest.
	 * 
	 * @return void
	 */
	private function buildParserExpression()
	{
		$this->parserExpression = '#^';
		for ($i = 0, $formatLength = strlen($this->format); $i < $formatLength; $i++) {
			if ($this->format[$i] !== '%') {
				$this->parserExpression .= $this->format[$i];
				continue;
			}

			switch ($this->format[++$i]) {
				case '%':
					$this->parserExpression .= '%';
					break;

				// %>s eseten
				case '>':
					if ($this->format[++$i] !== 's') {
						throw new ApacheLogParserException('Hibas formatum: ismeretlen elem a(z) '
							.($i - 2).' karakternel!');
					}
					$this->parserExpression .= self::$pattern['s'];
					break;

				// Specialis, valtozo nevu elem eseten: %{...}x
				case '{':
					$nextCurlyPosition = strpos($this->format, '}', $i);
					if ($nextCurlyPosition === false) {
						throw new ApacheLogParserException('Hibas formatum: a(z) '
							.$i.' karakternel talalhato \'{\'-nek nincs lezaro eleme!');
					}
					elseif ($nextCurlyPosition === $i + 1) {
						throw new ApacheLogParserException('Hibas formatum: a(z) '
							.$i.' karakternel kezdodo valtozo meghatarozasnak nincs erteke!');
					}
					$currentToken = substr($this->format, $i, $nextCurlyPosition - $i + 2);
					foreach (self::$pattern as $key => $value) {
						$match = array();
						if (preg_match('#^'.$key.'$#', $currentToken, $match)) {
							$this->parserExpression .= str_replace('%NAME%', strtolower(str_replace('-', '', $match['name'])), $value);
							$i = $nextCurlyPosition + 1;
							break 2;
						}
					}
					throw new ApacheLogParserException('Hibas formatum: a(z) '
						.$i.' karakterel kezdodo elem nem ertelmezheto!');
					break;

				default:
					if (isset(self::$pattern[$this->format[$i]])) {
						$this->parserExpression .= self::$pattern[$this->format[$i]];
					}
					else {
						throw new ApacheLogParserException('Hibas formatum: ismeretlen elem a(z) '.$i.' karakternel!');
					}
			}
		}
		
		$this->parserExpression .= '$#';
	}
	
	/**
	 * Visszaadja a megadott file sorainak ertekeit.
	 * 
	 * @param string $file   A feldolgozando log file eleresi utvonala.
	 * 
	 * @throws ApacheLogParserException   Amennyiben a feldolgozas soran hiba keletkezik
	 * @return array   A feldolgozott log sorok adatait tartalmazo tomb
	 */
	public function parse($file)
	{
		if (!is_readable($file)) {
			throw new ApacheLogParserException('A megadott file ['.$file.'] nem olvashato!');
		}
	}

	/**
	 * Visszaadja a megadott log sor ertekeit.
	 * 
	 * @param string $line   A feldolgozando log sor.
	 * 
	 * @return array   A feldolgozott log sor adatait tartalmazo asszociativ tomb.
	 */
	public function parseLine($line)
	{
		$match = array();
		preg_match($this->parserExpression, trim($line), $match);
		return $match;
	}
}

/**
 * Apache Log Parser Exception
 * 
 * @package ApacheLogParser
 */
class ApacheLogParserException extends Exception
{
}
