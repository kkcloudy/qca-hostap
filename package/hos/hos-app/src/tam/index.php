<?php
/**
 * Step 1: Require the Slim Framework
 *
 * If you are not using Composer, you need to require the
 * Slim Framework and register its PSR-0 autoloader.
 *
 * If you are using Composer, you can skip this step.
 */
require 'Slim/Slim.php';

\Slim\Slim::registerAutoloader();

/**
 * Step 2: Instantiate a Slim application
 *
 * This example instantiates a Slim application using
 * its default settings. However, you will usually configure
 * your Slim application now by passing an associative array
 * of setting names and values into the application constructor.
 */
$app = new \Slim\Slim();
$app->response->headers->set('Content-Type', 'application/json');
/**
 * Step 3: Define the Slim application routes
 *
 * Here we define several Slim application routes that respond
 * to appropriate HTTP request methods. In this example, the second
 * argument for `Slim::get`, `Slim::post`, `Slim::put`, `Slim::patch`, and `Slim::delete`
 * is an anonymous function.
 */

// GET route
$app->get(
    '/haps',
    function () {
		$haps = array(
					array(
						'mac' => '00:1F:64:E0:00:13',
						'ip' => '192.168.1.250',
						'status' => 'join'),
					array(
						'mac' => '00:1F:64:E0:00:14',
						'ip' => '192.168.1.251',
						'status' => 'join'));
		
		$response = array(
					'success' => true, 
					'result' => $haps);	
					
		/*$response = array(
					'success' => true, 
					'result' => 'Get HAP list success!');
				
		$response = array(
					'success' => false, 
					'error' => array(
								'code' => '10000', 
								'message' => 'Get HAP list fail!'));*/
		echo json_encode($response);
    }
);
$app->get(
    '/hap/:mac',
    function ($mac) {
		$hap = array(
					'mac' => '00:1F:64:E0:00:13',
					'ip' => '192.168.1.250',
					'status' => 'join');
		
		$response = array(
					'success' => true, 
					'result' => $hap);	
					
		/*$response = array(
					'success' => true, 
					'result' => 'Get HAP '.$mac.' success!');*/
        echo json_encode($response);
    }
);

// POST route
$app->post(
    '/haps',
    function () use ($app) {
		/*
		{
			"mac": "00:1F:64:E0:00:13",
			"ip": "192.168.1.250",
			"status": "join"
		}
		*/
		$requestBody = $app->request()->getBody();
		//print_r(json_decode($requestBody, true));
		//var_dump(json_decode($requestBody));

        $response = array(
					'success' => true, 
					'result' => 'Post HAP success!');
        echo json_encode($response);
    }
);

// PUT route
$app->put(
    '/hap/:mac',
    function ($mac) {
        $response = array(
					'success' => true, 
					'result' => 'Put HAP '.$mac.' success!');
        echo json_encode($response);
    }
);

// DELETE route
$app->delete(
    '/hap/:mac',
    function ($mac) {
        $response = array(
					'success' => true, 
					'result' => 'Delete HAP '.$mac.' success!');
        echo json_encode($response);
    }
);

/**
 * Step 4: Run the Slim application
 *
 * This method should be called last. This executes the Slim application
 * and returns the HTTP response to the HTTP client.
 */
$app->run();
?>