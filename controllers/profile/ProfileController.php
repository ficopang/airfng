<?php
require "../../database/db.php";
require "../../helpers/function.php";
require "../../helpers/auth.php";

if($_SERVER['REQUEST_METHOD'] == 'POST' && isset($_POST['update'])) {

    //////
    /// QUESTION 5 SECTION 3D OF 3: Cross-Site Request Forgery (CSRF) - Check Token
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
    /// QUESTION 3 SECTION 9A OF 12: Access Control
    /// Validate that only logged user can access this page
    /// SECTION STARTS HERE (DONE)
    //////

    if ((!isset($_SESSION['id']) || strcmp($_SESSION['id'], $_POST['id']) != 0) || (!isset($_SESSION['role']) || strcmp($_SESSION['role'], "admin") != 0)) {
        header("location: ../../auth/login.php");
    }

    //////
    /// SECTION ENDS HERE
    //////

    //////
    /// QUESTION 4 SECTION 2 OF 4: Cross-Site Scripting (XSS)
    /// Sanitize input based on requirement
    /// SECTION STARTS HERE (DONE)
    //////
    $firstName = htmlspecialchars(filter_var($_POST['first_name'], FILTER_SANITIZE_STRING));
    $lastName = htmlspecialchars(filter_var($_POST['last_name'], FILTER_SANITIZE_STRING));
    $gender = htmlspecialchars(filter_var($_POST['gender'], FILTER_SANITIZE_STRING));
    $about = strip_tags($_POST['about'], "<br><br/><strong><em>");
    $imgStatus = htmlspecialchars(filter_var($_POST['img_status'], FILTER_SANITIZE_STRING));
    //////
    /// SECTION ENDS HERE
    //////

    if (!check_empty_data([$firstName, $lastName, $gender, $imgStatus])){
        $_SESSION['error'] = "All fields must be filled";
        header("location: " . $_SERVER['HTTP_REFERER']);
        return;
    }

    if (!in_array($gender, [1, 2])) {
        $_SESSION['error'] = "Gender must between Male and Female";
        header("location: " . $_SERVER['HTTP_REFERER']);
        return;
    }

    if (isset($_POST['role']) && !in_array($_POST['role'], ["member", "admin"])) {
        $_SESSION['error'] = "Gender must between Member and Admin";
        header("location: " . $_SERVER['HTTP_REFERER']);
        return;
    }

    if (isset($_POST['role']) && $_SESSION['role'] !== 'admin'){
        $_SESSION['error'] = "Invalid Request";
        header("location: ../../");
        return;
    }

    if ($_FILES['file_upload']['size'] > 1024 * 1024 * 10){
        $_SESSION['error'] = "File is too big";
        header("location: " . $_SERVER['HTTP_REFERER']);
        return;
    }
    //////
    /// QUESTION 6 SECTION 4A OF 6: SQL Injection
    /// SECTION STARTS HERE (DONE)
    //////
    $id = $_POST['id'];
    $sql_check_user = "SELECT * from users WHERE id = ?";
    $stmt = $conn->prepare($sql_check_user);
    $stmt->bind_param("s", $id);

    if (!$stmt->execute()) {
        return;
    }

    $result = $stmt->get_result();
    $row = $result->fetch_assoc();

    $file_name = null;
    $dir = "../../assets/images/profile/";

    if ($imgStatus == 1){
        if ($row['photo'] != null && file_exists($dir . $row['photo'])) {
            unlink($dir . $row['photo']);
        }
        
        $file_name = $row['id'] . '_' . uniqid("") . '.' . 
            strtolower(pathinfo($_FILES["file_upload"]["name"],PATHINFO_EXTENSION));
    
        $target_file = $dir . $file_name;
    
        move_uploaded_file($_FILES["file_upload"]["tmp_name"], $target_file);
    } else if ($imgStatus == 2) {
        if ($row['photo'] != null && file_exists($dir . $row['photo'])) {
            unlink($dir . $row['photo']);
        }
    } else if ($imgStatus != 0){
        $_SESSION['error'] = "Invalid Request";
        header("location: ../../");
        return;
    }
        //////
        /// QUESTION 6 SECTION 4B OF 6: SQL Injection
        /// SECTION STARTS HERE (DONE)
        //////
        $sql = "";
        $statement = "";

        if ($imgStatus == 0){
            $sql = "UPDATE users set 
                first_name = ?, 
                last_name = ?, 
                gender = ?, 
                about = ?". 
                ((isset($_POST['role'])) ? ", role = '" . $_POST['role'] . "'" : "") . " where id = ?";

                $stmt = $conn->prepare($sql);
                $stmt->bind_param("sssss", $firstName, $lastName, $gender, $about, $id);

                if (!$stmt->execute()) {
                    return;
                }
            
        } else {
            $sql = "UPDATE users set 
            first_name = ?, 
            last_name = ?, 
            gender = ?, 
            about = ?,
            photo = ?". 
            ((isset($_POST['role'])) ? ", role = '" . $_POST['role'] . "'" : "") . " where id = ?";

            $stmt = $conn->prepare($sql);
            $stmt->bind_param("ssssss", $firstName, $lastName, $gender, $about, $photo, $id);

            if (!$stmt->execute()) {
                return;
            }
        }


        if ($_SESSION['id'] == $_POST['id']){
            $_SESSION['first_name'] = $firstName;
            $_SESSION['last_name'] = $lastName;
            $_SESSION['role'] = isset($_POST['role']) ? $_POST['role'] : "member";
            $_SESSION['photo'] = $file_name;
        }

        //////
        /// SECTION ENDS HERE
        //////

    //////
    /// SECTION ENDS HERE
    //////

    $_SESSION['success'] = 'Successfully update user';
    header("location: ../../index");
    return;


}

if($_SERVER['REQUEST_METHOD'] == 'POST' && isset($_POST['delete'])){
    //////
    /// QUESTION 5 SECTION 3E OF 3: Cross-Site Request Forgery (CSRF) - Check Token
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
    /// QUESTION 3 SECTION 9B OF 12: Access Control
    /// Validate that only logged user can access this page
    /// SECTION STARTS HERE (DONE)
    //////

    if (!isset($_SESSION['role']) || strcmp($_SESSION['role'], "admin") != 0) {
        header("location: ../../errors/403.html");
    }

    //////
    /// SECTION ENDS HERE
    //////

    $id = $_POST['id'];
    if (!check_empty_data([$id])){
        $_SESSION['error'] = "All fields must be filled";
        header("location: " . $_SERVER['HTTP_REFERER']);
        return;
    }
    //////
    /// QUESTION 6 SECTION 4C OF 6: SQL Injection
    /// SECTION STARTS HERE (DONE)
    //////
    $sql_check_user = "SELECT u.*, d.id as deleted_id from users u left join deleteditems d on u.id = d.data_id WHERE u.id = ?";
    $stmt = $conn->prepare($sql_check_user);
    $stmt->bind_param("s", $id);

    if (!$stmt->execute()) {
        return;
    }

    $result = $stmt->get_result();
    $row = $result->fetch_assoc();

    if ($result->num_rows != 1){
        $_SESSION['error'] = "Invalid user id";
        header("location: " . $_SERVER['HTTP_REFERER']);
        return;
    }

        //////
        /// QUESTION 6 SECTION 4D OF 6: SQL Injection
        /// SECTION STARTS HERE (DONE)
        ////// 
        if ($row['deleted_id'] == null){
            $current_id = $_SESSION['id'];
            $sql = "INSERT INTO deleteditems VALUES(uuid(), ?, ?, now())";

            $stmt = $conn->prepare($sql);
            $stmt->bind_param("ss", $id, $current_id);

            if (!$stmt->execute()) {
                return;
            }

            $_SESSION['success'] = 'Successfully blacklisted the user';
            header("location: ../../");
            return;
        } 
        //////
        /// SECTION ENDS HERE
        //////

        //////
        /// QUESTION 6 SECTION 4E OF 6: SQL Injection
        /// SECTION STARTS HERE (DONE)
        ////// 
        $sql = "delete from deleteditems where data_id = ?";

        $stmt = $conn->prepare($sql);
        $stmt->bind_param("s", $id);

        if (!$stmt->execute()) {
            return;
        }
        //////
        /// SECTION ENDS HERE
        //////        

    $_SESSION['success'] = 'Successfully removed the blacklist for the user';
    header("location: ../../");
    return;
    //////
    /// SECTION ENDS HERE
    //////
}

header("location: " . $_SERVER['HTTP_REFERER']);
return;