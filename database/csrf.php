<?php
//////
/// QUESTION 5 Cross-Site Request Forgery (CSRF) - SECTION 1 OF 3
/// Set Token Session
/// SECTION STARTS HERE (DONE)
//////

if ($_SERVER['REQUEST_METHOD'] == 'GET') {
    $key = bin2hex(random_bytes(32));
    $_SESSION['key'] = $key;
    $token = hash_hmac('sha256', '/form', $key);
}

//////
/// SECTION ENDS HERE
//////