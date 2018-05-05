<?php

(defined('APPPATH')) or exit('No direct script access allowed');
/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
$app = new system\SOE();
$app->get('/', function() {
    echo 'test';
}, 'Home');
$app->middleware('GET|POST', '/*', function () {
    echo 'middleware ------------ <br>';
});
$app->run();
