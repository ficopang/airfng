<?php
require "../../database/db.php";
require "../../helpers/function.php";
require "../../helpers/auth.php";

if($_SERVER['REQUEST_METHOD'] == 'POST' && isset($_POST['signup'])) {
    //////
    /// QUESTION 5 SECTION 3B OF 3: Cross-Site Request Forgery (CSRF) - Check Token
    /// SECTION STARTS HERE (DONE)
    //////

    $token = $_POST['_token'];
    $key = $_SESSION['key'];
    if (!hash_equals(hash_hmac('sha256', '/form', $key), $token)) {
        dd('CSRF ATTEMPT');
    }
        
    //////
    /// SECTION ENDS HERE
    //////


    $firstName = htmlspecialchars($_POST['first_name']);
    $lastName = htmlspecialchars($_POST['last_name']);
    $password = $_POST['password'];
    $email = htmlspecialchars($_POST['email']);
    $phoneNumber = htmlspecialchars($_POST['phone_number']);
    $gender = htmlspecialchars($_POST['gender']);
    $tnc = $_POST['tnc'];

    if ($firstName === '' 
        || $lastName === '' || $password === '' 
        || $email === '' || $phoneNumber === ''
        || $gender === '' || $tnc === '') {
        $_SESSION['error'] = "All fields must be filled";
        header("location: ../../auth/signup.php");
    } else if (!in_array($gender, [1, 2])) {
        $_SESSION['error'] = "Gender must between Male and Female";
        header("location: ../../auth/signup.php");
    } else if ($tnc != 1) {
        $_SESSION['error'] = "You must agree out terms and condition";
        header("location: ../../auth/signup.php");
    } else if (!preg_match('/^\d{10,13}$/', $phoneNumber)){
        $_SESSION['error'] = "Phone number must between [0-9]";
        header("location: ../../auth/signup.php");
    } else {
        //////
        /// QUESTION 2 SECTION 2 OF 2: Hashing Password
        /// SECTION STARTS HERE (DONE)
        //////

            $password = password_hash($password, PASSWORD_DEFAULT);

            $sql_check_email = "SELECT * from users WHERE email = '$email' or 
            phone_number = '$phoneNumber'";
            $result = $conn->query($sql_check_email);
            if ($result->num_rows > 0){
                $_SESSION['error'] = 'Email or Phone Number is already in use';
                header("location: ../../auth/signup.php");
                exit();
            } else {
                
            
                //////
                /// QUESTION 6 SECTION 2 OF 6: SQL Injection
                /// SECTION STARTS HERE (DONE)
                //////
    
                $sql = "INSERT INTO users VALUES(uuid(), ?, ?, ?, ?, ?, ?, 'member', null, null, now())";

                $stmt = $conn->prepare($sql);
                $stmt->bind_param("ssssss", $firstName, $lastName, $password, $email, $phoneNumber, $gender);

                if (!$stmt->execute()) {
                    return;
                }
                //////
                /// SECTION ENDS HERE
                //////
                $_SESSION['success'] = 'Successfully registered new user';
                header("location: ../../auth/login.php");
                return;
            }

        //////
        /// SECTION ENDS HERE
        //////
        

    }

    header("location: ../../auth/signup.php");
    return;
}

$_SESSION['error'] = 'Invalid Request';
header("location: ../../auth/signup.php");
exit();