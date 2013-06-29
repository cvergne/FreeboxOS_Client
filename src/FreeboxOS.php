<?php
/*=============================================
=            Freebox OS API Client            =
=============================================*/
/*
    It's a DRAFT, so don't use it for the moment.
    (c) 2013 Christophe VERGNE.
    Under MIT License

    RestAPIClient is based on the work of Travis Dent ( https://github.com/tcdent )
*/

class FreeboxOS {
    public $options;
    private $api_full_base_url;

    // APP data
    public $app;

    // Freebox API Vars
    private $uid;
    private $device_name;
    private $api_version='1.0';
    private $api_base_url='/api/';
    private $device_type;
    private $track_id;
    private $app_token;
    private $challenge;
    private $password;

    public function __construct($app=array(), $options=array())
    {
        // Check primary app informations
        $this->app = array_merge(array(
            'app_id' => NULL,
            'app_name' => NULL,
            'app_version' => NULL,
            'device_name' => NULL
        ), $app);
        foreach ($this->app as $key => $val) {
            if (empty($val)) {
                throw new Exception('the value of ' . $key . ' is missing');
            }
        }

        // Merge main options
        $this->options = array_merge(array(
            'freebox_ip' => 'http://mafreebox.freebox.fr',
            'freebox_local' => 'http://mafreebox.freebox.fr',
            'rest' => array(
                'headers' => array(
                    'Content-Type: application/json'
                )
            )
        ), $options);

        // Define Base URL
        $this->define_base_urls();

        // Define Token
        if (isset($this->options->app_token)) {
            $this->app_token = $this->options->app_token;
        }

        // Init API Client
        $this->API = new RestAPIClient($this->options['rest']);
    }

    /*==========  Login  ==========*/
    public function _autolog()
    {
        /*
            - Vérification que app_token est défini
                - sinon ->authorize()
                    - stockage de l'app_token et du track_id
                    - monitoring du tracking jusqu'à accès != 'pending'
                    - si 'granted':
            - récupération du challenge [->login_()]
            - génération du mot de passe et ouverture de session
        */

    }

    public function login_authorize()
    {
        $this->switch_to_local(true);
        $request = $this->API->post('login/authorize/', $this->app);

        $this->switch_to_local(false);

        return $request;
    }

    /*==========  UTILITIES  ==========*/
    public function check_api_version()
    {
        $request = $this->API->request($this->options['freebox_ip'] . '/api_version', 'GET', array(), array(), false);
        if ($request->info->http_code == 200) {
            $this->uid = $request->response->uid;
            $this->device_name = $request->response->device_name;
            $this->api_version = $request->response->api_version;
            $this->api_base_url = $request->response->api_base_url;
            $this->device_type = $request->response->device_type;

            $this->define_base_urls();

            return true;
        }
        else {
            return $request;
        }
    }

    private function define_base_urls()
    {
        $this->api_full_base_url = $this->api_base_url . 'v' . intval($this->api_version);

        $this->options['rest']['base_url'] = $this->options['freebox_ip'] . $this->api_full_base_url;
        $this->options['rest']['base_url_local'] = $this->options['freebox_local'] . $this->api_full_base_url;

        if (isset($this->API)) {
            $this->API->options['base_url'] = $this->options['rest']['base_url'];
            $this->API->options['base_url_local'] = $this->options['rest']['base_url_local'];
        }
    }

    private function switch_to_local($state=false)
    {
        $this->API->options['switch_base_url'] = $state;
    }

    private function password()
    {
        if ($this->app_token && $this->challenge) {
            $this->password = hash_hmac('sha1', $this->challenge, $this->app_token);
            return $this->password;
        }
        else {
            throw new Exception('Password gen error, missing app_token or challenge');

        }
    }
}

class RestAPIClient
{
    public $options;
    public $handle; // cURL resource handle.

    // Populated after execution:
    public $response; // Response body.
    public $headers; // Parsed reponse header object.
    public $info; // Response info object.
    public $error; // Response error string.

    public function __construct($options=array())
    {
        $this->options = array_merge(array(
            'headers' => array(),
            'curl_options' => array(),
            'base_url' => NULL,
            'base_url_local' => NULL,
            'switch_base_url' => false,
            'format' => NULL,
            'username' => NULL,
            'password' => NULL
        ), $options);
    }

    public function get($url, $parameters=array(), $headers=array())
    {
        return $this->request($url, 'GET', $parameters, $headers);
    }

    public function post($url, $parameters=array(), $headers=array())
    {
        return $this->request($url, 'POST', $parameters, $headers);
    }

    public function put($url, $parameters=array(), $headers=array())
    {
        $parameters['_method'] = "PUT";
        return $this->post($url, $parameters, $headers);
    }

    public function delete($url, $parameters=array(), $headers=array())
    {
        $parameters['_method'] = "DELETE";
        return $this->post($url, $parameters, $headers);
    }

    public function parse_response($response)
    {
        $headers = array();
        $http_ver = strtok($response, "\n");

        while($line = strtok("\n")){
            if(strlen(trim($line)) == 0) break;

            list($key, $value) = explode(':', $line, 2);
            $key = trim(strtolower(str_replace('-', '_', $key)));
            $value = trim($value);
            if(empty($headers[$key])){
                $headers[$key] = $value;
            }
            elseif(is_array($headers[$key])){
                $headers[$key][] = $value;
            }
            else {
                $headers[$key] = array($headers[$key], $value);
            }
        }

        $this->headers = (object) $headers;
        $this->response = json_decode(strtok(""));
    }

    public function request($url, $method='GET', $parameters=array(), $headers=array(), $use_base_url=true)
    {
        $client = clone $this;

        $client->url = $url;
        $client->handle = curl_init();

        $curl_options = array(
            CURLOPT_HEADER => TRUE,
            CURLOPT_RETURNTRANSFER => TRUE,
            CURLOPT_TIMEOUT => 20
        );

        // Mix default headers and custom request headers
        if(count($client->options['headers']) || count($headers)) {
            $curl_options[CURLOPT_HTTPHEADER] = array();

            $headers = array_merge($client->options['headers'], $headers);

            foreach ($headers as $key => $value) {
                $curl_options[CURLOPT_HTTPHEADER][] = sprintf("%s:%s", $key, $value);
            }
        }

        // Format query
        if (count($parameters)) {
            $curl_options[CURLOPT_POSTFIELDS] = json_encode($parameters);
        }

        // Define Base URL
        if ($use_base_url) {
            if ($client->options['switch_base_url'] && $client->options['base_url_local']) {
                $base_url = $client->options['base_url_local'];
            }
            else {
                $base_url = $client->options['base_url'];
            }
            if($base_url){
                if($client->url[0] != '/' || substr($base_url, -1) != '/')
                    $client->url = '/' . $client->url;
                $client->url = $base_url . $client->url;
            }
        }
        $curl_options[CURLOPT_URL] = $client->url;

        // Additional CURL Options
        if($client->options['curl_options']){
            // array_merge would reset our numeric keys.
            foreach($client->options['curl_options'] as $key => $value){
                $curl_options[$key] = $value;
            }
        }
        curl_setopt_array($client->handle, $curl_options);

        // Exec and parse request
        $client->parse_response(curl_exec($client->handle));
        $client->info = (object) curl_getinfo($client->handle);
        $client->error = curl_error($client->handle);

        curl_close($client->handle);
        return $client;
    }
}