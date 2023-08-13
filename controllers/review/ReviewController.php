<?php
require "../../database/db.php";
require "../../helpers/function.php";
require "../../helpers/auth.php";

if ($_SERVER['REQUEST_METHOD'] == 'POST' && isset($_POST['create'])){
    //////
    /// QUESTION 5 SECTION 3F OF 3: Cross-Site Request Forgery (CSRF) - Check Token
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

    //////
    /// QUESTION 3 7 OF 12: Access Control
    /// Validate that only logged user can access this page
    /// SECTION STARTS HERE (DONE)
    //////

    if (!isset($_SESSION['id'])) {
        header("location: ../../auth/login.php");
    }

    //////
    /// SECTION ENDS HERE
    //////

    //////
    /// QUESTION 4 SECTION 3 OF 4: Cross-Site Scripting (XSS)
    /// Sanitize input based on requirement
    /// SECTION STARTS HERE (DONE)
    //////
    $hostId = $_POST['host_id'];
    $review = strip_tags($_POST['review'], "<br><br/><strong><em>");
    //////
    /// SECTION ENDS HERE
    //////
    
    //////
    /// QUESTION 6 SECTION 5A OF 6: SQL Injection
    /// SECTION STARTS HERE (DONE)
    //////
    $userId = $_SESSION['id'];
    $sql_check_transaction = "SELECT * from transactions WHERE host_id = ? 
    and user_id = ?";

    $stmt = $conn->prepare($sql_check_transaction);
    $stmt->bind_param("ss", $hostId, $userId);

    if (!$stmt->execute()) {
        return;
    }

    $result = $stmt->get_result();

    if ($result->num_rows < 1){
        $_SESSION['error'] = "Invalid Forum Request!";
        header("location: " . $_SERVER['HTTP_REFERER']);
        return;
    }

    if($review === ''){
        $_SESSION['error'] = "All fields must be filled";
        header("location: " . $_SERVER['HTTP_REFERER']);
        return;
    } else {
        $row = $result->fetch_assoc();
        $hostId = $row['host_id'];
        //////
        /// QUESTION 6 SECTION 5B OF 6: SQL Injection
        /// SECTION STARTS HERE (DONE)
        //////
        $sql_check_forum = "SELECT * from reviews WHERE host_id = ? and user_id = ?";
        $stmt = $conn->prepare($sql_check_forum);
        $stmt->bind_param("ss", $hostId, $userId);

        if (!$stmt->execute()) {
            return;
        }

        $result = $stmt->get_result();

        if ($result->num_rows < 1){
            //////
            /// QUESTION 6 SECTION 5C OF 6: SQL Injection
            /// SECTION STARTS HERE (DONE)
            //////
            $sql = "INSERT INTO reviews VALUES('$hostId', '$userId', '$review', now())";

            $stmt = $conn->prepare($query);
            $stmt->bind_param("sss", $hostId, $userId, $review);

            if (!$stmt->execute()) {
                return;
            }
            //////
            /// SECTION ENDS HERE
            //////
            $_SESSION['success'] = 'Successfully add new forum';
            header("location: ../../");
            return;
        } else {
            //////
            /// QUESTION 6 SECTION 5D OF 6: SQL Injection
            /// SECTION STARTS HERE (DONE)
            //////
            $sql = "UPDATE reviews set review = '$review', 
                created_at = now() where host_id = ? and user_id = ?";
            $stmt = $conn->prepare($sql);
            $stmt->bind_param("ss", $hostId, $userId);

            if (!$stmt->execute()) {
                return;
            }
            //////
            /// SECTION ENDS HERE
            //////
            $_SESSION['success'] = 'Successfully update forum';
            header("location: ../../");
            return;
        }  
        //////
        /// SECTION ENDS HERE
        //////    
    }
    //////
    /// SECTION ENDS HERE
    //////
    
}