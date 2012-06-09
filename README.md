Opauth-LinkedIn
=============
[Opauth][1] strategy for LinkedIn, implemented based on https://developer.linkedin.com/documents/authentication using OAuth.

Opauth is a multi-provider authentication framework for PHP.

Demo: http://opauth.org

Getting started
----------------
1. Install Opauth-LinkedIn:
   ```bash
   cd path_to_opauth/Strategy
   git clone git://github.com/uzyn/opauth-linkedin.git LinkedIn
   ```

2. Create LinkedIn application at https://www.linkedin.com/secure/developer
   - Enter your domain at JavaScript API Domain  
   - There is no need to enter OAuth Redirect URL
	
3. Configure Opauth-LinkedIn strategy with at least `qpi_key` and `secret_key`.

4. Direct user to `http://path_to_opauth/linkedin` to authenticate

Strategy configuration
----------------------
Required parameters:

```php
<?php
'LinkedIn' => array(
	'api_key' => 'YOUR API KEY',
	'secret_key' => 'YOUR SECRET KEY'
),
```

See LinkedInStrategy.php for optional parameters.


Dependencies
------------
Opauth-LinkedIn includes tmhOAuth, which requires hash_hmac and cURL.  
hash_hmac is available on PHP 5 >= 5.1.2.

License
---------
Opauth-LinkedIn is MIT Licensed  
Copyright © 2012 U-Zyn Chua (http://uzyn.com)

tmhOAuth is [Apache 2 licensed](https://github.com/themattharris/tmhOAuth/blob/master/LICENSE).

[1]: https://github.com/uzyn/opauth