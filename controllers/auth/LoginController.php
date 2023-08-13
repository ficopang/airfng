<?php
require "../../database/db.php";
require "../../helpers/function.php";
require "../../helpers/auth.php";

if ($_SERVER['REQUEST_METHOD'] == 'POST' && isset($_POST['login'])){
    //////
    /// QUESTION 5 SECTION 3A OF 3: Cross-Site Request Forgery (CSRF) - Check Token
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

    $email = $_POST['email'];
    $password = $_POST['password'];

    if ($password === '' || $email === '') {
        $_SESSION['error'] = "All fields must be filled";
        header("location: ../../auth/login.php");
        return;
    } else {
        //////
        /// QUESTION 2 SECTION 1 OF 2: Hashing Password
        /// SECTION STARTS HERE (DONE)
        //////

            //////
            /// QUESTION 6 SECTION 1 OF 6: SQL Injection
            /// SECTION STARTS HERE (DONE)
            //////
            
                $sql = "SELECT u.*, d.id as deleted_id FROM users u left join deleteditems d
                on d.data_id = u.id
                WHERE email = ?";
                $stmt = $conn->prepare($sql);
                $stmt->bind_param("s", $email);

                if (!$stmt->execute()) {
                    return;
                }

                $result = $stmt->get_result();
            
            //////
            /// SECTION ENDS HERE
            //////

        if($result->num_rows > 0) {
            //////
            /// QUESTION 1 SECTION 1 OF 2: Generate New Session
            /// SECTION STARTS HERE (DONE)
            //////

            session_regenerate_id();

            //////
            /// SECTION ENDS HERE
            //////

            $row = $result->fetch_assoc();

            if ($row['deleted_id'] !== null){
                $_SESSION['error'] = 'This account has been blocked from this site by admin!';

                header("location: ../../");
                return;
            }

            if (password_verify($password, $row['password'])){
                $_SESSION['id'] = $row['id'];
                $_SESSION['email'] = $row['email'];
                $_SESSION['first_name'] = $row['first_name'];
                $_SESSION['last_name'] = $row['last_name'];
                $_SESSION['role'] = $row['role'];
                $_SESSION['photo'] = $row['photo'];
        
                if($_POST['remember']) {
                    //////
                    /// QUESTION 8 SECTION 1 OF 1: HTTP Header
                    /// SECTION STARTS HERE (DONE)
                    //////

                    header('Access-Control-Allow-Origin: http://localhost');
                    header('Access-Control-Allow-Methods: GET,POST,HEAD,OPTIONS,DELETE,PUT');
                    header('Access-Control-Allow-Headers: *');
                    setcookie("email", $email, time() + (3600 * 24 * 3));
                    setcookie("password", $password, time() + (3600 * 24 * 3));
        
                    //////
                    /// SECTION ENDS HERE
                    //////
                }

                header("location: ../../");
                return;
            }

            else {
                $_SESSION['error'] = 'Wrong password';

                header("location: ../../auth/login.php");
                return;
            }
            
            
        } 

        //////
        /// SECTION ENDS HERE
        //////
        $_SESSION['error'] = 'Invalid email';
        header("location: ../../auth/login.php");
        return;

    }
    //////
    /// SECTION ENDS HERE
    //////
}

header("location: ../auth/login.php");
return;