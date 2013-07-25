# Freebox OS API PHP Client

A PHP Client to use the Freebox OS API

**It's a DRAFT, use it at your own risk**

Currently, the helper handles :

* Auth methods
* Download's methods ( *except Download Trackers & Download Peers, because they are unstable* )
* FileSystem's methods ( *except downloading file* )

Currently, you can check [issue #1](https://github.com/cvergne/FreeboxOS_Client/issues/1) to have the list of handled methods.

## Warning
Currently, the only way to authorize an app is to call API methods on your local network.

**That means you have to call this script the first time on localhost for example to get the App Token.**

This helper is still in developpment, main process or methods could change in near future.

## How to use it ?
```php
<?php
    session_start(); // Currently needed, but will be optionnal in near future
    require('FreeboxOS.php');

    $fbx = new FreeboxOS(array(
        'app_id' => 'fr.freebox.testapp',
        'app_name' => 'Test App',
        'app_version' => '0.0.7',
        'device_name' => 'Mac de Chris'
    ),
    array(
        /* If you have the App Token, you can pass it directly to the options to set it */
        // 'app_token' => 'dyNYgfK0Ya6FWGqq83sBHa7TwzWo+pg4fDFUJHShcjVYzTfaRrZzm93p7OTAfH/0',
        'freebox_ip' =>  'http://204.232.175.90'
    ));
    
    /* App Token is automatically stored in Session and reused in each instance for the same $app data.
        After the first instance, you can also get the App Token with the following method :
    */
    $app_token = $fbx->getAppToken();
?>
```

### Options
* `freebox_ip` : Set your external freebox ip address ( ___mandatory___ if you use it out of your localhost )
* `monitor_wait` : (default: `5`) Set the time (in seconds) to wait before check again the authorization. Don't put a too high value or it could reach the maximum execution time of your php configuration.
* `fs` : Array()
    * `conflict_mode` : (default: `both`) Set the default conflict_mode to use in FS methods if you don't specify one in method options. Please refer to Freebox API Documentation for values.


-----------
The MIT License (MIT)

Copyright (c) 2013 Christophe VERGNE

Permission is hereby granted, free of charge, to any person obtaining a copy of
this software and associated documentation files (the "Software"), to deal in
the Software without restriction, including without limitation the rights to
use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of
the Software, and to permit persons to whom the Software is furnished to do so,
subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS
FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR
COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER
IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.

        
          
