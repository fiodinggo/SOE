<?php

/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */

/**
 * Description of SOE
 *
 * @author nidas
 */

namespace system;

class SOE extends Controlling {

    private $routes = array();
    private $middlewares = array();
    protected $notFound;
    private $basic_ruting = '';
    private $method = '';
    private $pl = '';
    private $resposneHeaders = array();
    private $pola = array();

    public function __construct(array $options = array()) {
        parent::__construct();
        $defaultOptions = array(
            'x-powered-by' => "fti-uksw"
        );
        $this->resposneHeaders = array_merge($defaultOptions, $options);
    }

    public function base_url() {
        $base_url = ((isset($_SERVER['HTTPS']) && $_SERVER['HTTPS'] == "on") ? "https" : "http");
        $base_url .= "://" . $_SERVER['HTTP_HOST'];
        $base_url .= str_replace(basename($_SERVER['SCRIPT_NAME']), "", $_SERVER['SCRIPT_NAME']);
        return $base_url;
    }

    private function match($methods, $pola, $fungsi, $ket) {

        $pola = $this->basic_ruting . '/' . trim($pola, '/');
        $pola = $this->basic_ruting ? rtrim($pola, '/') : $pola;

        foreach (explode('|', $methods) as $method) {
            $this->routes[$method][$pola] = array(
                'pola' => $pola,
                'fn' => $fungsi,
                'keterangan' => $ket
            );
            $this->pola[$method][$pola] = '';
        }
    }

    public function middleware($methods, $pola, $fn) {

        $pola = $this->basic_ruting . '/' . trim($pola, '/');
        $pola = $this->basic_ruting ? rtrim($pola, '/') : $pola;

        foreach (explode('|', $methods) as $method) {
            ((strpos($pola, '*')) ? $this->looppola($pola, $method, $fn) : $this->singlepola($pola, $method, $fn));
        }
    }

    private function singlepola($pola, $method, $fn) {
        $this->pola[$method][$pola] = 'middleware';
        $this->middlewares[$method][$pola] = array(
            'pola' => $pola,
            'fn' => $fn
        );
    }

    private function looppola($pola, $method, $fn) {
        $pl = substr($pola, 0, -1);
//        echo $pl;
        foreach ($this->pola[$method] as $k => $v) {
            $valpola = ((substr($k, 0, strlen($pl)) === $pl) ? 'middleware' : '');
            $this->pola[$method][$k] = $valpola;
            ((substr($k, 0, strlen($pl)) === $pl) ? ($this->middlewares[$method][$k] = array(
                'pola' => $pola,
                'fn' => $fn
            )) : '');
        }
//        echo '<pre>';
//        print_r($this->middlewares);
//        echo '</pre>';
    }

    public function all($pola, $fungsi, $ket) {
        $this->match('GET|POST|PUT|DELETE|OPTIONS|PATCH|HEAD', $pola, $fungsi, $ket);
        $this->pl = $pola;
        return $this;
    }

    public function get($pola, $fungsi, $ket) {
        $this->match('GET', $pola, $fungsi, $ket);
//        $this->pl = $pola;
        return $this;
    }

    public function post($pola, $fungsi, $ket) {
        $this->match('POST', $pola, $fungsi, $ket);
//        $this->pl = $pola;
        return $this;
    }

    public function patch($pola, $fungsi, $ket) {
        $this->match('PATCH', $pola, $fungsi, $ket);
        $this->pl = $pola;
        return $this;
    }

    public function delete($pola, $fungsi, $ket) {
        $this->match('DELETE', $pola, $fungsi, $ket);
        $this->pl = $pola;
        return $this;
    }

    public function put($pola, $fungsi, $ket) {
        $this->match('PUT', $pola, $fungsi, $ket);
        $this->pl = $pola;
        return $this;
    }

    public function options($pola, $fungsi, $ket) {
        $this->match('OPTIONS', $pola, $fungsi, $ket);
        $this->pl = $pola;
        return $this;
    }

    public function group($basic_ruting, $fungsi) {
        $curBaseroute = $this->basic_ruting;
        $this->basic_ruting .= $basic_ruting;
        call_user_func($fungsi);
        $this->basic_ruting = $curBaseroute;
        return $this;
    }

    public function getRequestMethod() {
        $method = $_SERVER['REQUEST_METHOD'];
        if ($_SERVER['REQUEST_METHOD'] == 'HEAD') {
            ob_start();
            $method = 'GET';
        } elseif ($_SERVER['REQUEST_METHOD'] == 'POST') {
            $headers = $this->getRequestHeaders();
            if (isset($headers['X-HTTP-Method-Override']) && in_array($headers['X-HTTP-Method-Override'], array('PUT', 'DELETE', 'PATCH'))) {
                $method = $headers['X-HTTP-Method-Override'];
            }
        }

        return $method;
    }

    public function run($callback = null) {
        $this->method = $this->getRequestMethod();
        $base_url = ((isset($_SERVER['HTTPS']) && $_SERVER['HTTPS'] == "on") ? "https" : "http");
        $base_url .= "://" . $_SERVER['HTTP_HOST'];
        $actvurl = $base_url . $_SERVER['REQUEST_URI'];
        $base_url .= str_replace(basename($_SERVER['SCRIPT_NAME']), "", $_SERVER['SCRIPT_NAME']);
        $requesturl = '/' . substr($actvurl, strlen($base_url), strlen($actvurl));
//        echo '<pre>';
//        print_r($this->middlewares[$this->method][$requesturl]['fn']);
//        echo '</pre>';
//        echo '<pre>';
//        print_r($this->pola[$this->method][$requesturl]);
//        echo '</pre>';
        ((isset($this->pola[$this->method][$requesturl]) && $this->pola[$this->method][$requesturl] == 'middleware') ? call_user_func($this->middlewares[$this->method][$requesturl]['fn']) : '');
        $this->execute($callback);
    }

    private function execute($callback) {
//        if (isset($this->routes[$this->method])) {
//            $numHandled = $this->handle($this->routes[$this->method], true);
//        }
        $numHandled = (isset($this->routes[$this->method]) ? ($this->handle($this->routes[$this->method], true)) : 0);
//        foreach ($this->resposneHeaders as $k => $v){
//            header("$k: $v");
//        }
        if ($numHandled === 0) {
            if ($this->notFound && is_callable($this->notFound)) {
                call_user_func($this->notFound);
            } else {
                $this->httpstatus('404');
            }
        } else {
            $this->httpstatus('200');
            (isset($callback) ? $callback() : $this->notFound);
        }
        foreach ($this->resposneHeaders as $k => $v) {
            header("$k: $v");
        }

//        if ($_SERVER['REQUEST_METHOD'] == 'HEAD') {
//            ob_end_clean();
//        }

        if ($numHandled === 0) {
            return false;
        }
        return true;
    }

    private function handle($routes, $quitAfterRun = false) {
        $numHandled = 0;
        $uri = $this->getCurrentUri();
        foreach ($routes as $route) {
            if (preg_match_all('#^' . $route['pola'] . '$#', $uri, $matches, PREG_OFFSET_CAPTURE)) {
                $matches = array_slice($matches, 1);
                $params = array_map(function ($match, $index) use ($matches) {
                    if (isset($matches[$index + 1]) && isset($matches[$index + 1][0]) && is_array($matches[$index + 1][0])) {
                        return trim(substr($match[0][0], 0, $matches[$index + 1][0][1] - $match[0][1]), '/');
                    } else {
                        return (isset($match[0][0]) ? trim($match[0][0], '/') : null);
                    }
                }, $matches, array_keys($matches));
                call_user_func_array($route['fn'], $params);
                $numHandled++;
                if ($quitAfterRun) {
                    break;
                }
            }
        }
        return $numHandled;
    }

    public function set404($fungsi) {
        $this->notFound = $fungsi;
    }

    public function httpstatus($kode) {
        $httpstatus = array(
            '200' => $_SERVER['SERVER_PROTOCOL'] . ' 200 Ok',
            '201' => $_SERVER['SERVER_PROTOCOL'] . ' 201 Created',
            '202' => $_SERVER['SERVER_PROTOCOL'] . ' 202 Accepted',
            '203' => $_SERVER['SERVER_PROTOCOL'] . ' 203 Non-Authoritative Information',
            '204' => $_SERVER['SERVER_PROTOCOL'] . ' 204 No Content',
            '205' => $_SERVER['SERVER_PROTOCOL'] . ' 205 Reset Content',
            '206' => $_SERVER['SERVER_PROTOCOL'] . ' 206 Partial Content',
            
            '300' => $_SERVER['SERVER_PROTOCOL'] . ' 300 Multiple Choice',
            '301' => $_SERVER['SERVER_PROTOCOL'] . ' 301 Moved Permanently',
            '302' => $_SERVER['SERVER_PROTOCOL'] . ' 302 Found',
            '303' => $_SERVER['SERVER_PROTOCOL'] . ' 303 See Other',
            '304' => $_SERVER['SERVER_PROTOCOL'] . ' 304 Not Modified',
            '305' => $_SERVER['SERVER_PROTOCOL'] . ' 305 Use Proxy',
            '306' => $_SERVER['SERVER_PROTOCOL'] . ' 306 unused',
            '307' => $_SERVER['SERVER_PROTOCOL'] . ' 307 Temporary Redirect',
            '308' => $_SERVER['SERVER_PROTOCOL'] . ' 308 Permanent Redirect',
            
            '400' => $_SERVER['SERVER_PROTOCOL'] . ' 400 Bad Request',
            '401' => $_SERVER['SERVER_PROTOCOL'] . ' 401 Unauthorized',
            '402' => $_SERVER['SERVER_PROTOCOL'] . ' 402 Payment Required',
            '403' => $_SERVER['SERVER_PROTOCOL'] . ' 403 Forbidden',
            '404' => $_SERVER['SERVER_PROTOCOL'] . ' 404 Not Found',
            '405' => $_SERVER['SERVER_PROTOCOL'] . ' 405 Method Not Allowed',
            '406' => $_SERVER['SERVER_PROTOCOL'] . ' 406 Not Acceptable',
            '407' => $_SERVER['SERVER_PROTOCOL'] . ' 407 Proxy Authentication Required',
            '408' => $_SERVER['SERVER_PROTOCOL'] . ' 408 Request Timeout',
            '409' => $_SERVER['SERVER_PROTOCOL'] . ' 409 Conflict',
            '410' => $_SERVER['SERVER_PROTOCOL'] . ' 410 Gone',
            '411' => $_SERVER['SERVER_PROTOCOL'] . ' 411 Length Required',
            '412' => $_SERVER['SERVER_PROTOCOL'] . ' 412 Precondition Failed',
            '413' => $_SERVER['SERVER_PROTOCOL'] . ' 413 Payload Too Large',
            '414' => $_SERVER['SERVER_PROTOCOL'] . ' 414 URI Too Long',
            '415' => $_SERVER['SERVER_PROTOCOL'] . ' 415 Unsupported Media Type',
            '416' => $_SERVER['SERVER_PROTOCOL'] . ' 416 Requested Range Not Satisfiable',
            '417' => $_SERVER['SERVER_PROTOCOL'] . ' 417 Expectation Failed',
            '421' => $_SERVER['SERVER_PROTOCOL'] . ' 421 Misdirected Request',
            '426' => $_SERVER['SERVER_PROTOCOL'] . ' 426 Upgrade Required',
            '428' => $_SERVER['SERVER_PROTOCOL'] . ' 428 Precondition Required',
            '429' => $_SERVER['SERVER_PROTOCOL'] . ' 429 Too Many Requests',
            '431' => $_SERVER['SERVER_PROTOCOL'] . ' 431 Request Header Fields Too Large',
            '451' => $_SERVER['SERVER_PROTOCOL'] . ' 451 Unavailable For Legal Reasons',
            
            '500' => $_SERVER['SERVER_PROTOCOL'] . ' 500 Internal Server Error',
            '501' => $_SERVER['SERVER_PROTOCOL'] . ' 501 Not Implemented',
            '502' => $_SERVER['SERVER_PROTOCOL'] . ' 502 Bad Gateway',
            '503' => $_SERVER['SERVER_PROTOCOL'] . ' 503 Service Unavailable',
            '504' => $_SERVER['SERVER_PROTOCOL'] . ' 504 Gateway Timeout',
            '505' => $_SERVER['SERVER_PROTOCOL'] . ' 505 HTTP Version Not Supported',
            '506' => $_SERVER['SERVER_PROTOCOL'] . ' 506 Variant Also Negotiates',
            '507' => $_SERVER['SERVER_PROTOCOL'] . ' 507 Variant Also Negotiates',
            '511' => $_SERVER['SERVER_PROTOCOL'] . ' 511 Network Authentication Required'
        );
        header($httpstatus[$kode]);
    }

    public function httpcache($isi) {
        $last_modified_time = filemtime($isi);
        $etag = md5_file($file);

        header("Last-Modified: " . gmdate("D, d M Y H:i:s", $last_modified_time) . " GMT");
        header("Etag: $etag");

        if (@strtotime($_SERVER['HTTP_IF_MODIFIED_SINCE']) == $last_modified_time || trim($_SERVER['HTTP_IF_NONE_MATCH']) == $etag) {
            header("HTTP/1.1 304 Not Modified");
            exit;
        }
    }

}

class Controlling {

    private $globals = array();
    protected $notFound;
    protected $_enable_xss = false;
    protected $_xss_hash;
    public $charset = 'UTF-8';
    protected $_never_allowed_str = array(
        'document.cookie' => '[removed]',
        'document.write' => '[removed]',
        '.parentNode' => '[removed]',
        '.innerHTML' => '[removed]',
        '-moz-binding' => '[removed]',
        '<!--' => '&lt;!--',
        '-->' => '--&gt;',
        '<![CDATA[' => '&lt;![CDATA[',
        '<comment>' => '&lt;comment&gt;',
        '<%' => '&lt;&#37;'
    );
    protected $_never_allowed_regex = array(
        'javascript\s*:',
        '(document|(document\.)?window)\.(location|on\w*)',
        'expression\s*(\(|&\#40;)', // CSS and IE
        'vbscript\s*:', // IE, surprise!
        'wscript\s*:', // IE
        'jscript\s*:', // IE
        'vbs\s*:', // IE
        'Redirect\s+30\d',
        "([\"'])?data\s*:[^\\1]*?base64[^\\1]*?,[^\\1]*?\\1?"
    );

    public function __construct() {
        
    }

    public function getRequestHeaders() {
        if (function_exists('getallheaders')) {
            return getallheaders();
        }
        $headers = array();
        foreach ($_SERVER as $name => $value) {
            if ((substr($name, 0, 5) == 'HTTP_') || ($name == 'CONTENT_TYPE') || ($name == 'CONTENT_LENGTH')) {
                $headers[str_replace(array(' ', 'Http'), array('-', 'HTTP'), ucwords(strtolower(str_replace('_', ' ', substr($name, 5)))))] = $value;
            }
        }
        return $headers;
    }

    protected function getCurrentUri() {
        $basepath = implode('/', array_slice(explode('/', $_SERVER['SCRIPT_NAME']), 0, -1)) . '/';
        $uri = substr($_SERVER['REQUEST_URI'], strlen($basepath));
        if (strstr($uri, '?')) {
            $uri = substr($uri, 0, strpos($uri, '?'));
        }
        $uri = '/' . trim($uri, '/');

        return $uri;
    }

    public function model($sModelName) {
        $sModelFile = APPPATH . 'models' . $sModelName . ".php";
        if (file_exists($sModelFile)) {
            include_once($sModelFile);
            return new $sModelName();
        } else {
            return "Class model tidak ditemukan.";
        }
    }

    public function library($libname) {
        $libfile = APPPATH . 'libraries/' . $libname . ".lib.php";
        if (file_exists($libfile)) {
            require_once($libfile);
            return new $libname;
        } else {
            echo "Class library tidak ditemukan.";
        }
    }

    public function controller($sConName, $fn = 'index') {
        $sConFile = APPPATH . 'controller/' . $sConName . ".php";
        if (file_exists($sConFile)) {
            require_once $sConFile;
            $v = new $sConName();
            if (method_exists($v, $fn) != false) {
                return $v->$fn();
            } else {
                echo "function $fn tidak ditemukan pada class $sConName.";
            }
        } else {
            echo "Class Controller tidak ditemukan.";
        }
    }

    public function view($file, $arr = array(), $return = false) {
        $tpl = APPPATH . 'view/' . $file . '.php';
        if (file_exists($tpl)) {
            foreach ($arr as $key => $value) {
                $$key = $value;
            }
            unset($arr);

            foreach ($this->globals as $key => $value) {
                $$key = $value;
            }

            ob_start();
            require_once( $tpl );
            $template = ob_get_contents();
            ob_end_clean();

            if ($return == false) {
                echo $template;
            } else {
                return $template;
            }
        } else {
            return false;
        }
    }

    private function extract_parameter() {
        $list = array();
        if ($_SERVER['REQUEST_METHOD'] == 'GET') {
            foreach ($_GET as $k => $v) {
                if ($k || $v) {
                    $list[$k] = $v;
                }
            }
        } else {
            $queryString = file_get_contents("php://input");
            parse_str($queryString, $list);
        }
        return $list;
    }

    public function input($prm = '', $xss_clean = null) {
        is_bool($xss_clean) OR $xss_clean = $this->_enable_xss;
        $param = $this->extract_parameter();
        $a = '';
        if ($prm != '') {
            if (is_array($param[$prm])) {
                echo 'array';
                $list = array();
                foreach ($param as $k => $v) {
                    $list[$k] = stripslashes(strip_tags(htmlspecialchars($v, ENT_QUOTES)));
                }
                $a = $list;
            } else {
                $vl = stripslashes(strip_tags(htmlspecialchars($param[$prm], ENT_QUOTES)));
                $a = ($xss_clean === TRUE) ? $this->xss_clean($vl) : $vl;
            }
        } else {
            $a = $param;
        }
        return $a;
    }

    public function xss_clean($str, $is_image = FALSE) {
        if (is_array($str)) {
            foreach ($str as $key => &$value) {
                $str[$key] = $this->xss_clean($value);
            }

            return $str;
        }
        $str = $this->remove_invisible_characters($str);
        if (stripos($str, '%') !== false) {
            do {
                $oldstr = $str;
                $str = rawurldecode($str);
                $str = preg_replace_callback('#%(?:\s*[0-9a-f]){2,}#i', array($this, '_urldecodespaces'), $str);
            } while ($oldstr !== $str);
            unset($oldstr);
        }
        $str = preg_replace_callback("/[^a-z0-9>]+[a-z0-9]+=([\'\"]).*?\\1/si", array($this, '_convert_attribute'), $str);
        $str = preg_replace_callback('/<\w+.*/si', array($this, '_decode_entity'), $str);
        $str = $this->remove_invisible_characters($str);

        $str = str_replace("\t", ' ', $str);

        $converted_string = $str;

        $str = $this->_do_never_allowed($str);

        if ($is_image === TRUE) {
            $str = preg_replace('/<\?(php)/i', '&lt;?\\1', $str);
        } else {
            $str = str_replace(array('<?', '?' . '>'), array('&lt;?', '?&gt;'), $str);
        }
        $words = array(
            'javascript', 'expression', 'vbscript', 'jscript', 'wscript',
            'vbs', 'script', 'base64', 'applet', 'alert', 'document',
            'write', 'cookie', 'window', 'confirm', 'prompt', 'eval'
        );

        foreach ($words as $word) {
            $word = implode('\s*', str_split($word)) . '\s*';
            $str = preg_replace_callback('#(' . substr($word, 0, -3) . ')(\W)#is', array($this, '_compact_exploded_words'), $str);
        }
        do {
            $original = $str;

            if (preg_match('/<a/i', $str)) {
                $str = preg_replace_callback('#<a(?:rea)?[^a-z0-9>]+([^>]*?)(?:>|$)#si', array($this, '_js_link_removal'), $str);
            }

            if (preg_match('/<img/i', $str)) {
                $str = preg_replace_callback('#<img[^a-z0-9]+([^>]*?)(?:\s?/?>|$)#si', array($this, '_js_img_removal'), $str);
            }

            if (preg_match('/script|xss/i', $str)) {
                $str = preg_replace('#</*(?:script|xss).*?>#si', '[removed]', $str);
            }
        } while ($original !== $str);
        unset($original);
        $pattern = '#'
                . '<((?<slash>/*\s*)((?<tagName>[a-z0-9]+)(?=[^a-z0-9]|$)|.+)'
                . '[^\s\042\047a-z0-9>/=]*'
                . '(?<attributes>(?:[\s\042\047/=]*'
                . '[^\s\042\047>/=]+'
                . '(?:\s*='
                . '(?:[^\s\042\047=><`]+|\s*\042[^\042]*\042|\s*\047[^\047]*\047|\s*(?U:[^\s\042\047=><`]*))'
                . ')?'
                . ')*)'
                . '[^>]*)(?<closeTag>\>)?#isS';
        do {
            $old_str = $str;
            $str = preg_replace_callback($pattern, array($this, '_sanitize_naughty_html'), $str);
        } while ($old_str !== $str);
        unset($old_str);
        $str = preg_replace(
                '#(alert|prompt|confirm|cmd|passthru|eval|exec|expression|system|fopen|fsockopen|file|file_get_contents|readfile|unlink)(\s*)\((.*?)\)#si', '\\1\\2&#40;\\3&#41;', $str
        );
        $str = $this->_do_never_allowed($str);
        if ($is_image === TRUE) {
            return ($str === $converted_string);
        }
        return $str;
    }

    protected function _urldecodespaces($matches) {
        $input = $matches[0];
        $nospaces = preg_replace('#\s+#', '', $input);
        return ($nospaces === $input) ? $input : rawurldecode($nospaces);
    }

    protected function _convert_attribute($match) {
        return str_replace(array('>', '<', '\\'), array('&gt;', '&lt;', '\\\\'), $match[0]);
    }

    protected function _decode_entity($match) {
        $match = preg_replace('|\&([a-z\_0-9\-]+)\=([a-z\_0-9\-/]+)|i', $this->xss_hash() . '\\1=\\2', $match[0]);
        return str_replace(
                $this->xss_hash(), '&', $this->entity_decode($match, $this->charset)
        );
    }

    protected function _do_never_allowed($str) {
        $str = str_replace(array_keys($this->_never_allowed_str), $this->_never_allowed_str, $str);

        foreach ($this->_never_allowed_regex as $regex) {
            $str = preg_replace('#' . $regex . '#is', '[removed]', $str);
        }

        return $str;
    }

    protected function remove_invisible_characters($str, $url_encoded = TRUE) {
        $non_displayables = array();
        if ($url_encoded) {
            $non_displayables[] = '/%0[0-8bcef]/i'; // url encoded 00-08, 11, 12, 14, 15
            $non_displayables[] = '/%1[0-9a-f]/i'; // url encoded 16-31
            $non_displayables[] = '/%7f/i'; // url encoded 127
        }

        $non_displayables[] = '/[\x00-\x08\x0B\x0C\x0E-\x1F\x7F]+/S'; // 00-08, 11, 12, 14-31, 127

        do {
            $str = preg_replace($non_displayables, '', $str, -1, $count);
        } while ($count);

        return $str;
    }

    public function entity_decode($str, $charset = NULL) {
        if (strpos($str, '&') === FALSE) {
            return $str;
        }

        static $_entities;

        isset($charset) OR $charset = $this->charset;
        $flag = is_php('5.4') ? ENT_COMPAT | ENT_HTML5 : ENT_COMPAT;

        if (!isset($_entities)) {
            $_entities = array_map('strtolower', get_html_translation_table(HTML_ENTITIES, $flag, $charset));

            // If we're not on PHP 5.4+, add the possibly dangerous HTML 5
            // entities to the array manually
            if ($flag === ENT_COMPAT) {
                $_entities[':'] = '&colon;';
                $_entities['('] = '&lpar;';
                $_entities[')'] = '&rpar;';
                $_entities["\n"] = '&NewLine;';
                $_entities["\t"] = '&Tab;';
            }
        }

        do {
            $str_compare = $str;

            // Decode standard entities, avoiding false positives
            if (preg_match_all('/&[a-z]{2,}(?![a-z;])/i', $str, $matches)) {
                $replace = array();
                $matches = array_unique(array_map('strtolower', $matches[0]));
                foreach ($matches as &$match) {
                    if (($char = array_search($match . ';', $_entities, TRUE)) !== FALSE) {
                        $replace[$match] = $char;
                    }
                }

                $str = str_replace(array_keys($replace), array_values($replace), $str);
            }

            // Decode numeric & UTF16 two byte entities
            $str = html_entity_decode(
                    preg_replace('/(&#(?:x0*[0-9a-f]{2,5}(?![0-9a-f;])|(?:0*\d{2,4}(?![0-9;]))))/iS', '$1;', $str), $flag, $charset
            );

            if ($flag === ENT_COMPAT) {
                $str = str_replace(array_values($_entities), array_keys($_entities), $str);
            }
        } while ($str_compare !== $str);
        return $str;
    }

    protected function _compact_exploded_words($matches) {
        return preg_replace('/\s+/s', '', $matches[1]) . $matches[2];
    }

    protected function _js_link_removal($match) {
        return str_replace(
                $match[1], preg_replace(
                        '#href=.*?(?:(?:alert|prompt|confirm)(?:\(|&\#40;)|javascript:|livescript:|mocha:|charset=|window\.|document\.|\.cookie|<script|<xss|d\s*a\s*t\s*a\s*:)#si', '', $this->_filter_attributes($match[1])
                ), $match[0]
        );
    }

    protected function _js_img_removal($match) {
        return str_replace(
                $match[1], preg_replace(
                        '#src=.*?(?:(?:alert|prompt|confirm|eval)(?:\(|&\#40;)|javascript:|livescript:|mocha:|charset=|window\.|document\.|\.cookie|<script|<xss|base64\s*,)#si', '', $this->_filter_attributes($match[1])
                ), $match[0]
        );
    }

    protected function _sanitize_naughty_html($matches) {
        static $naughty_tags = array(
            'alert', 'area', 'prompt', 'confirm', 'applet', 'audio', 'basefont', 'base', 'behavior', 'bgsound',
            'blink', 'body', 'embed', 'expression', 'form', 'frameset', 'frame', 'head', 'html', 'ilayer',
            'iframe', 'input', 'button', 'select', 'isindex', 'layer', 'link', 'meta', 'keygen', 'object',
            'plaintext', 'style', 'script', 'textarea', 'title', 'math', 'video', 'svg', 'xml', 'xss'
        );

        static $evil_attributes = array(
            'on\w+', 'style', 'xmlns', 'formaction', 'form', 'xlink:href', 'FSCommand', 'seekSegmentTime'
        );

        // First, escape unclosed tags
        if (empty($matches['closeTag'])) {
            return '&lt;' . $matches[1];
        }
        // Is the element that we caught naughty? If so, escape it
        elseif (in_array(strtolower($matches['tagName']), $naughty_tags, TRUE)) {
            return '&lt;' . $matches[1] . '&gt;';
        }
        // For other tags, see if their attributes are "evil" and strip those
        elseif (isset($matches['attributes'])) {
            // We'll store the already fitlered attributes here
            $attributes = array();

            // Attribute-catching pattern
            $attributes_pattern = '#'
                    . '(?<name>[^\s\042\047>/=]+)' // attribute characters
                    // optional attribute-value
                    . '(?:\s*=(?<value>[^\s\042\047=><`]+|\s*\042[^\042]*\042|\s*\047[^\047]*\047|\s*(?U:[^\s\042\047=><`]*)))' // attribute-value separator
                    . '#i';

            // Blacklist pattern for evil attribute names
            $is_evil_pattern = '#^(' . implode('|', $evil_attributes) . ')$#i';

            // Each iteration filters a single attribute
            do {
                // Strip any non-alpha characters that may precede an attribute.
                // Browsers often parse these incorrectly and that has been a
                // of numerous XSS issues we've had.
                $matches['attributes'] = preg_replace('#^[^a-z]+#i', '', $matches['attributes']);

                if (!preg_match($attributes_pattern, $matches['attributes'], $attribute, PREG_OFFSET_CAPTURE)) {
                    // No (valid) attribute found? Discard everything else inside the tag
                    break;
                }

                if (
                // Is it indeed an "evil" attribute?
                        preg_match($is_evil_pattern, $attribute['name'][0])
                        // Or does it have an equals sign, but no value and not quoted? Strip that too!
                        OR ( trim($attribute['value'][0]) === '')
                ) {
                    $attributes[] = 'xss=removed';
                } else {
                    $attributes[] = $attribute[0][0];
                }

                $matches['attributes'] = substr($matches['attributes'], $attribute[0][1] + strlen($attribute[0][0]));
            } while ($matches['attributes'] !== '');

            $attributes = empty($attributes) ? '' : ' ' . implode(' ', $attributes);
            return '<' . $matches['slash'] . $matches['tagName'] . $attributes . '>';
        }

        return $matches[0];
    }

}
