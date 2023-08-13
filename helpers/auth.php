<?php

if (!function_exists('login_user')){
    function login_user(){
        return isset($_SESSION['id']);
    }
}

