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
    private $session_vars = array('uid', 'device_name', 'api_version', 'api_base_url', 'device_type', 'app_token', 'track_id', 'auth_status', 'challenge', 'password', 'session_token', 'permissions');

    // APP data
    public $app;
    public $app_uid;

    // Freebox API Vars
    private $uid;
    public $device_name;
    private $api_version='1.0';
    private $api_base_url='/api/';
    public $device_type;
    private $app_token;
    private $track_id;
    public $auth_status;
    private $challenge;
    private $password;
    private $session_token;
    public $permissions;

    public $logged_in=false;

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
        $this->app_uid = sha1($this->app['app_id'].$this->app['app_name'].$this->app['app_version'].$this->app['device_name']);

        // Merge main options
        $this->options = array_merge(array(
            'use_session' => true,
            'freebox_ip' => 'http://mafreebox.freebox.fr',
            'freebox_local' => 'http://mafreebox.freebox.fr',
            'monitor_wait' => 5, // in seconds
            'rest' => array(
                'headers' => array(
                    'Content-Type' => 'application/json'
                )
            ),
            'fs' => array(
                'conflict_mode' => 'both'
            )
        ), $options);

        // Check PHP Session to autostart (if enabled)
        $this->checkPHPSession(true);

        // Define Base URL
        $this->defineBaseUrls();

        // Define Token
        if (isset($this->options['app_token']) && !empty($this->options['app_token'])) {
            $this->app_token = $this->options['app_token'];
        }

        // Init API Client
        $this->API = new RestAPIClient($this->options['rest']);

        // Define PHP Session
        $this->getSessionVars()->setSessionVars();

        // Autolog
        $this->login_Autolog();
    }

    /*==========  Login  ==========*/
    public function login_Autolog()
    {
        if (!$this->app_token) {
            $this->login_Authorize();
            $this->login_Monitortrack();
        }

        if ($this->checkPHPSession() && isset($_SESSION['FreeboxOSAPI'][$this->app_uid]['session_token'])) {
            $this->session_token = $_SESSION['FreeboxOSAPI'][$this->app_uid]['session_token'];
            $this->setSession();
        }
        $this->login_Challenge();

        if (!$this->logged_in && !$this->session_token) {
            $this->login_Session(true);
        }

        $this->setSessionVars();

        return $this;
    }

    public function login_Authorize()
    {
        $this->switchToLocal(true);
        $request = $this->API->post('login/authorize/', $this->app);
        $this->switchToLocal(false);

        if ($request->info->http_code == 200 && $request->response->success) {
            $this->app_token = $request->response->result->app_token;
            if ($this->checkPHPSession()) {
                $_SESSION['FreeboxOSAPI'][$this->app_uid]['app_token'] = $this->app_token;
            }
            $this->track_id = $request->response->result->track_id;
        }
        else if (!$request->response->success) {
            $this->error($request);
        }

        return $request;
    }

    public function login_Monitortrack()
    {
        $this->login_Track();
        if ($this->auth_status == 'pending') {
            sleep($this->options['monitor_wait']);
            $this->login_Monitortrack();
        }
    }

    public function login_Track()
    {
        if ($this->track_id) {
            $this->switchToLocal(true);
            $request = $this->API->get('login/authorize/' . $this->track_id);
            $this->switchToLocal(false);

            if ($request->info->http_code == 200 && $request->response->success) {
                $this->challenge = $request->response->result->challenge;
                $this->auth_status = $request->response->result->status;
                return $this->auth_status;
            }
            else if (!$request->response->success) {
                $this->error($request);
                return false;
            }
        }
        else {
            throw new Exception('Missing Track ID. Run authorize first or pass an app_token.');
        }

        return false;
    }

    public function login_Challenge()
    {
        $request = $this->API->get('login/');
        if ($request->info->http_code == 200 && $request->response->success) {
            $this->logged_in = $request->response->result->logged_in;
            if (isset($request->response->result->challenge)) {
                $this->challenge = $request->response->result->challenge;
            }
        }
        else if (!$request->response->success) {
            $this->error($request);
        }

        return $request;
    }

    public function login_Session($skip_challenge=false)
    {
        if (!$skip_challenge && !$this->logged_in && !$this->challenge) {
            $this->login_Challenge();
        }
        if (!$this->logged_in) {
            if ($this->app_token && $this->challenge) {
                $this->password = hash_hmac('sha1', $this->challenge, $this->app_token);
            }
            else {
                throw new Exception('Error Password set, missing app_token or challenge');
            }
            $request = $this->API->post('login/session/', array(
                'app_id' => $this->app['app_id'],
                'password' => $this->password
            ));
            if ($request->info->http_code == 200 && $request->response->success) {
                $this->session_token = $request->response->result->session_token;
                if ($this->checkPHPSession()) {
                    $_SESSION['FreeboxOSAPI'][$this->app_uid]['session_token'] = $this->session_token;
                }

                $this->setSession();

                if ($request->response->result->permissions) {
                    $this->permissions = $request->response->result->permissions;
                }

                $this->logged_in = true;

                return true;
            }
            else if (!$request->response->success) {
                // Perform auto re-log if challenge has expired
                if (in_array($request->response->error_code, array('invalid_token', 'pending_token'))) {
                    $this->setChallenge($request);
                    $this->login_Session();
                }
                else {
                    $this->error($request);
                }
            }

            return false;
        }

        return true;
    }

    public function getAppToken()
    {
        return $this->app_token;
    }

    /*==========  Downloads  ==========*/
    public function downloads_List()
    {
        $this->checkPermission('downloader');

        $request = $this->API->get('downloads/');
        return $this->finalize_request($request);
    }

    public function downloads_Item($id)
    {
        $this->checkPermission('downloader');

        $request = $this->API->get('downloads/' . intval($id));
        if ($request->info->http_code == 200 && $request->response->success) {
            $request->response->result->download_dir_name = utf8_decode(base64_decode($request->response->result->download_dir));
        }
        return $this->finalize_request($request);
    }

    public function downloads_Remove($id, $erase_files=false)
    {
        $this->checkPermission('downloader');

        $path = 'downloads/' . intval($id);
        if ($erase_files) {
            $path .= '/erase';
        }

        $request = $this->API->delete($path);
        return $this->finalize_request($request);
    }

    public function downloads_Update($id, $data)
    {
        $this->checkPermission('downloader');

        if (is_array($data)) {
            $request = $this->API->put('downloads/' . intval($id), $data);
            return $this->finalize_request($request);
        }
        else {
            $this->error($data, 'Data passed must be an array');
        }
    }

    public function downloads_Log($id)
    {
        $this->checkPermission('downloader');

        $request = $this->API->get('downloads/' . intval($id) . '/log');
        return $this->finalize_request($request);
    }

    public function downloads_addURL($data, $use_raw=false)
    {
        $this->checkPermission('downloader');

        if (!$use_raw)
        {
            if (isset($data['download_url']) && is_array($data['download_url'])) {
                $data['download_url_list'] = $data['download_url'];
                unset($data['download_url']);
            }

            if (isset($data['download_url_list']) && is_array($data['download_url_list'])) {
                $data['download_url_list'] = implode("\n", $data['download_url_list']);
            }

            if (isset($data['recursive'])) {
                $data['recursive'] = boolval($data['recursive']);
            }
        }

        $request = $this->API->post('downloads/add', $data, array(
            'Content-Type' => 'application/x-www-form-urlencoded'
        ), array(
            CURLOPT_POST => TRUE
        ));

        return $this->finalize_request($request);
    }

    public function downloads_addFile($data, $use_raw=false)
    {
        $this->checkPermission('downloader');

        if (!$use_raw)
        {
            if (isset($data['download_file']) && strpos($data['download_file'], '@') !== 0) {
                $data['download_file'] = '@' . realpath($data['download_file']);
            }
        }

        $request = $this->API->post('downloads/add', $data, array(
            'Content-Type' => null // avoid overwrite of auto content-type "multipart/form-data" by "application/json"
        ), array(
            CURLOPT_POST => TRUE // auto content-type and manage file transfer
        ));

        return $this->finalize_request($request);
    }

    public function downloads_Stats()
    {
        $this->checkPermission('downloader');

        $request = $this->API->get('downloads/stats/');
        return $this->finalize_request($request);
    }

    public function downloads_FilesList($id)
    {
        $this->checkPermission('downloader');

        $request = $this->API->get('downloads/' . intval($id) . '/files');
        return $this->finalize_request($request);
    }

    public function downloads_getConfiguration()
    {
        $this->checkPermission('downloader');

        $request = $this->API->get('downloads/config/');
        return $this->finalize_request($request);
    }

    public function downloads_updateConfiguration($config)
    {
        $this->checkPermission('downloader');

        $request = $this->API->put('downloads/config/', $config);
        return $this->finalize_request($request);
    }

    public function downloads_updateThrottling($config)
    {
        $this->checkPermission('downloader');

        $request = $this->API->put('downloads/throttling/', $config);
        return $this->finalize_request($request);
    }

    /*==========  FILE SYSTEM  ==========*/
    public function fs_listEveryTasks()
    {
        $this->checkPermission('explorer');

        $request = $this->API->get('fs/tasks/');
        return $this->finalize_request($request);
    }

    public function fs_listTask($id)
    {
        $this->checkPermission('explorer');

        $request = $this->API->get('fs/tasks/' . intval($id));
        return $this->finalize_request($request);
    }

    public function fs_removeDoneTasks($state_to_remove=array('done'))
    {
        $tasks = $this->fs_listEveryTasks();
        $return = array();

        if ($tasks->success && count($tasks->result)) {
            foreach($tasks->result as $task) {
                if (in_array($task->state, $state_to_remove)) {
                    $request = $this->fs_deleteTask($task->id);
                    $return[$task->id] = $request->success;
                }
            }
        }

        return $return;
    }

    public function fs_deleteTask($id)
    {
        $this->checkPermission('explorer');

        $request = $this->API->delete('fs/tasks/' . intval($id));
        return $this->finalize_request($request);
    }

    public function fs_updateTask($id, $parameters=array())
    {
        $this->checkPermission('explorer');

        $request = $this->API->put('fs/tasks/' . intval($id), $parameters);
        return $this->finalize_request($request);
    }

    public function fs_listFiles($path, $parameters=array('removeHidden' => true))
    {
        $this->checkPermission('explorer');

        $request = $this->API->get('fs/ls/' . $path . '?' . http_build_query($parameters));
        return $this->finalize_request($request);
    }

    public function fs_fileInfo($path)
    {
        $this->checkPermission('explorer');

        $request = $this->API->get('fs/info/' . $path);
        return $this->finalize_request($request);
    }

    public function fs_fileMove($parameters)
    {
        $this->checkPermission('explorer');

        if (!isset($parameters['mode'])) {
            $parameters['mode'] = $this->options['fs']['conflict_mode'];
        }

        $request = $this->API->post('fs/mv/', $parameters);
        return $this->finalize_request($request);
    }

    public function fs_copyFile($parameters)
    {
        $this->checkPermission('explorer');

        if (!isset($parameters['mode'])) {
            $parameters['mode'] = $this->options['fs']['conflict_mode'];
        }

        $request = $this->API->post('fs/cp/', $parameters);
        return $this->finalize_request($request);
    }

    public function fs_removeFile($files)
    {
        $this->checkPermission('explorer');

        $request = $this->API->post('fs/rm/', array('files' => $files));
        return $this->finalize_request($request);
    }

    public function fs_catFiles($parameters)
    {
        $this->checkPermission('explorer');

        $request = $this->API->post('fs/cat/', $parameters);
        return $this->finalize_request($request);
    }

    public function fs_createArchive($parameters)
    {
        $this->checkPermission('explorer');

        if (!isset($parameters['dst'])) {
            $parameters['dst'] = 'L0Rpc3F1ZSBkdXI=';
        }

        $request = $this->API->post('fs/archive/', $parameters);
        return $this->finalize_request($request);
    }

    public function fs_extractArchive($parameters)
    {
        $this->checkPermission('explorer');

        if (!isset($parameters['src'], $parameters['dst'])) {
            $fileinfo = $this->fs_fileInfo($parameters['src']);
            if ($fileinfo->success) {
                $parameters['dst'] = $fileinfo->result->parent;
            }
        }

        $request = $this->API->post('fs/extract/', $parameters);
        return $this->finalize_request($request);
    }

    public function fs_repairFile($file, $delete_archive=false)
    {
        $this->checkPermission('explorer');

        $request = $this->API->post('fs/repair/', array(
            'src' => $file,
            'delete_archive' => boolval($delete_archive)
        ));
        return $this->finalize_request($request);
    }

    public function fs_hashFile($file, $hash_type='md5')
    {
        $this->checkPermission('explorer');

        $request = $this->API->post('fs/hash/', array(
            'src' => $file,
            'hash_type' => $hash_type
        ));
        return $this->finalize_request($request);
    }

    public function fs_getHashValue($id)
    {
        $this->checkPermission('explorer');

        $request = $this->API->get('fs/tasks/' . intval($id) . '/hash');
        return $this->finalize_request($request);
    }

    public function fs_createDirectory($parent, $name)
    {
        $this->checkPermission('explorer');

        $request = $this->API->post('fs/mkdir/', array(
            'parent' => $parent,
            'dirname' => $name
        ));
        return $this->finalize_request($request);
    }

    public function fs_renameItem($src, $dst)
    {
        $this->checkPermission('explorer');

        $request = $this->API->post('fs/rename/', array(
            'src' => $src,
            'dst' => $dst
        ));
        return $this->finalize_request($request);
    }

    public function fs_downloadFile($path)
    {
        $this->checkPermission('explorer');

        $request = $this->API->get('dl/' . $path, array(), array('_download' => true));
        return $this->finalize_request($request);

        return false; // Not working
    }

    /*==========  STORAGE  ==========*/
    public function storage_diskList()
    {
        $this->checkPermission('explorer');

        $request = $this->API->get('storage/disk/');
        return $this->finalize_request($request);
    }

    public function storage_diskInfo($id)
    {
        $this->checkPermission('explorer');

        $request = $this->API->get('storage/disk/' . intval($id));
        return $this->finalize_request($request);
    }

    public function storage_partitionList()
    {
        $this->checkPermission('explorer');

        $request = $this->API->get('storage/partition/');
        return $this->finalize_request($request);
    }

    public function storage_partitionInfo($id)
    {
        $this->checkPermission('explorer');

        $request = $this->API->get('storage/partition/' . intval($id));
        return $this->finalize_request($request);
    }

    /*==========  CALLS/CONTACTS  ==========*/
    public function call_logList()
    {
        $this->checkPermission('calls');

        $request = $this->API->get('call/log/');
        return $this->finalize_request($request);
    }


    /*==========  UTILITIES  ==========*/
    public function checkPHPSession($autostart=false)
    {
        if ($autostart && $this->options['use_session'] && ((function_exists('session_status') && session_status() == PHP_SESSION_NONE) || session_id() != '')) {
            @session_start();
            return true;
        }
        else {
            return ($this->options['use_session'] && ((function_exists('session_status') && session_status() == PHP_SESSION_ACTIVE) || session_id() != ''));
        }

        return false;
    }

    public function checkPermission($id=NULL)
    {
        // Auto re-connect if not logged
        if (!$this->logged_in) {
            $this->login_Challenge();
            if (!$this->logged_in) {
                $this->login_Session();
            }
            $this->setSessionVars();
        }

        if ($id && !$this->permissions->{$id}) {
            throw new Exception('Access denied for this app to ' . $id);
        }
    }

    public function checkApiVersion()
    {
        $request = $this->API->request($this->options['freebox_ip'] . '/api_version', 'GET', array(), array(), false);
        if ($request->info->http_code == 200) {
            $this->uid = $request->response->uid;
            $this->device_name = $request->response->device_name;
            $this->api_version = $request->response->api_version;
            $this->api_base_url = $request->response->api_base_url;
            $this->device_type = $request->response->device_type;

            $this->defineBaseUrls();

            return true;
        }
        else {
            return $request;
        }
    }

    private function defineBaseUrls()
    {
        $this->api_full_base_url = $this->api_base_url . 'v' . intval($this->api_version);

        $this->options['rest']['base_url'] = $this->options['freebox_ip'] . $this->api_full_base_url;
        $this->options['rest']['base_url_local'] = $this->options['freebox_local'] . $this->api_full_base_url;

        if (isset($this->API)) {
            $this->API->options['base_url'] = $this->options['rest']['base_url'];
            $this->API->options['base_url_local'] = $this->options['rest']['base_url_local'];
        }
    }

    private function switchToLocal($state=false)
    {
        $this->API->options['switch_base_url'] = $state;
    }

    private function setChallenge($request)
    {
        if (isset($request->response->result->challenge)) {
            $this->challenge = $request->response->result->challenge;
        }
    }

    private function setSession()
    {
        if ($this->session_token) {
            $session_auth_headers = $this->session_token;
            $this->options['rest']['headers']['X-Fbx-App-Auth'] = $session_auth_headers;
            $this->API->options['headers']['X-Fbx-App-Auth'] = $session_auth_headers;
        }
    }

    private function setSessionVars()
    {
        if ($this->checkPHPSession()) {
            if ($this->app_uid) {
                if (!isset($_SESSION['FreeboxOSAPI'])) {
                    $_SESSION['FreeboxOSAPI'] = array();
                }
                if (!isset($_SESSION['FreeboxOSAPI'][$this->app_uid])) {
                    $_SESSION['FreeboxOSAPI'][$this->app_uid] = array();
                }

                foreach ($this->session_vars as $v) {
                    if (!empty($this->{$v})) {
                        $_SESSION['FreeboxOSAPI'][$this->app_uid][$v] = $this->{$v};
                    }
                }
            }
        }

        return $this;
    }

    private function getSessionVars()
    {
        if ($this->checkPHPSession()) {
            if ($this->app_uid && isset($_SESSION['FreeboxOSAPI']) && isset($_SESSION['FreeboxOSAPI'][$this->app_uid])) {
                foreach ($this->session_vars as $v) {
                    if (isset($_SESSION['FreeboxOSAPI'][$this->app_uid][$v]) && !empty($_SESSION['FreeboxOSAPI'][$this->app_uid][$v])) {
                        $this->{$v} = $_SESSION['FreeboxOSAPI'][$this->app_uid][$v];
                    }
                }
            }
        }

        return $this;
    }

    private function finalize_request($request)
    {
        if ($request->info->http_code == 200 && $request->response->success) {
            return $request->response;
        }
        else if (!$request->response->success) {
            $this->error($request);
            return false;
        }
    }

    private function error($request, $addmessage='')
    {
        var_dump($request);
        throw new Exception($addmessage . ' [' . $request->response->error_code . '] ' . $request->response->msg);
    }
}

class RestAPIClient
{
    public $options;
    public $handle; // cURL ressource

    public $response;
    public $headers;
    public $info;
    public $error;

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

    public function get($url, $parameters=array(), $headers=array(), $curl_opt=array())
    {
        return $this->request($url, 'GET', $parameters, $headers, $curl_opt);
    }

    public function post($url, $parameters=array(), $headers=array(), $curl_opt=array())
    {
        return $this->request($url, 'POST', $parameters, $headers, $curl_opt);
    }

    public function put($url, $parameters=array(), $headers=array(), $curl_opt=array())
    {
        $curl_opt[CURLOPT_CUSTOMREQUEST] = "PUT";
        return $this->post($url, $parameters, $headers, $curl_opt);
    }

    public function delete($url, $parameters=array(), $headers=array(), $curl_opt=array())
    {
        $curl_opt[CURLOPT_CUSTOMREQUEST] = "DELETE";
        return $this->post($url, $parameters, $headers, $curl_opt);
    }

    public function parse_response($response, $header_size=0)
    {
        $headers = array();
        if ($header_size > 0) {
            $head = substr($response, 0, $header_size);
            $body = substr($response, $header_size);
        }
        $http_ver = strtok($head, "\n");

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
        $this->response = json_decode($body);
    }

    public function request($url, $method='GET', $parameters=array(), $headers=array(), $curl_opt=array(), $use_base_url=true)
    {
        $client = clone $this;
        $_download = false;
        if (isset($headers['_download'])) {
            $_download = true;
            unset($headers['_download']);
        }

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
                if (!empty($value)) {
                    $curl_options[CURLOPT_HTTPHEADER][] = sprintf("%s:%s", $key, $value);
                }
            }
        }

        if(count($curl_opt)) {
            foreach($curl_opt as $key => $value){
                $curl_options[$key] = $value;
            }
        }
        // Format query
        if (count($parameters)) {
            // Build query parameters as classic form instead of JSON if CURL POST is set to true
            if ((count($curl_opt) && isset($curl_opt[CURLOPT_POST]) && $curl_opt[CURLOPT_POST] === true)
                || (count($curl_options) && isset($curl_options[CURLOPT_POST]) && $curl_options[CURLOPT_POST] === true)) {
                if (isset($headers['Content-Type']) && $headers['Content-Type'] == 'application/x-www-form-urlencoded') {
                    $curl_options[CURLOPT_POSTFIELDS] = http_build_query($parameters);
                }
                else {
                    $curl_options[CURLOPT_POSTFIELDS] = $parameters;
                }
            }
            else {
                $curl_options[CURLOPT_POSTFIELDS] = json_encode($parameters);
            }
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
        // var_dump($curl_options);

        // Exec and parse request
        $curl_exec = curl_exec($client->handle);
        if ($_download) {
            // Download
        }
        else {
            $client->parse_response($curl_exec, curl_getinfo($client->handle, CURLINFO_HEADER_SIZE));
            $client->info = (object) curl_getinfo($client->handle);
            $client->error = curl_error($client->handle);
        }

        curl_close($client->handle);

        return $client;
    }
}