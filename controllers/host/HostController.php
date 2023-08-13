<?php
require "../../database/db.php";
require "../../helpers/function.php";
require "../../helpers/auth.php";

if ($_SERVER['REQUEST_METHOD'] == 'POST' && isset($_POST['create'])){
    //////
    /// QUESTION 5 SECTION 3C OF 3: Cross-Site Request Forgery (CSRF) - Check Token
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
    /// QUESTION 3 SECTION 6 OF 12: Access Control
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
    /// QUESTION 4 SECTION 1 OF 4: Cross-Site Scripting (XSS)
    /// Sanitize input based on requirement
    /// SECTION STARTS HERE (DONE)
    //////
    $name = htmlspecialchars(filter_var($_POST['name'], FILTER_SANITIZE_STRING));
    $price = htmlspecialchars(filter_var($_POST['price'], FILTER_SANITIZE_STRING));
    $city = htmlspecialchars(filter_var($_POST['city'], FILTER_SANITIZE_STRING));
    $street_address = htmlspecialchars(filter_var($_POST['street_address'], FILTER_SANITIZE_STRING));
    $rules = strip_tags($_POST['rules'], "<br><br/><strong><em>");
    $room = $_POST['room'];
    $room_quantity = $_POST['room_quantity'];
    //////
    /// SECTION ENDS HERE
    //////

    if($name === '' || $price === '' 
        || $city === '' || $street_address === ''
        || $rules === '' || in_array('', $room) || in_array('', $room_quantity)){
        
        $_SESSION['error'] = "All fields must be filled";
        header("location: ../../host/create.php");
        return;
    } else if (count($room) !== count($room_quantity)){
        $_SESSION['error'] = "Invalid input";
        header("location: ../../host/create.php");
        return;
    } else if ($_FILES['file_upload']['size'] > 1024 * 1024 * 10){
        $_SESSION['error'] = "File is too big";
        header("location: ../../host/create.php");
        return;
    } else if (!ctype_digit($price)){
        $_SESSION['error'] = "Price must be in integer format";
        header("location: ../../host/create.php");
        return;
    }

    foreach($room_quantity as $q){
        if (!ctype_digit($q) || $q < 1){
            $_SESSION['error'] = "Invalid room quantity input";
            header("location: ../../host/create.php");
            return;
        }
    }
    //////
    /// QUESTION 6 SECTION 3A OF 6: SQL Injection
    /// SECTION STARTS HERE (DONE)
    //////
    $sql_check_city = "SELECT * from cities WHERE id = '$city'";
    $stmt = $conn->prepare($sql_check_city);
    $stmt->bind_param("s", $email);

    if (!$stmt->execute()) {
        return;
    }

    $result = $stmt->get_result();
    if ($result->num_rows > 0){
        $dir = "../../assets/images/host/";
        $file_name = $_SESSION['id'] . '_' . uniqid("") . '.' . 
            strtolower(pathinfo($_FILES["file_upload"]["name"],PATHINFO_EXTENSION));

        $target_file = $dir . $file_name;

        move_uploaded_file($_FILES["file_upload"]["tmp_name"], $target_file);

        $result = [];
        foreach($room as $key => $value){
            $data['room_name'] = $value;
            $data['quantity'] = $room_quantity[$key];
            array_push($result, $data);
        }
        //////
        /// QUESTION 6 SECTION 3B OF 6: SQL Injection
        /// SECTION STARTS HERE (DONE)
        //////
        $id = $_SESSION['id'];
        $result = json_encode($result);
        $sql = "INSERT INTO hosts VALUES(uuid(), ?, ?, ?, ?, ? ,?, ?, ?, now())";

        $stmt = $conn->prepare($sql);
        $stmt->bind_param("ssisssss", $id, $name, $price, $file_name, $city, $street_address, $rules, $result);

        if (!$stmt->execute()) {
            return;
        }


        //////
        /// SECTION ENDS HERE
        //////

        $_SESSION['success'] = 'Successfully host a new home!';
        header("location: ../../");
        return;
    } else {
        $_SESSION['error'] = "Invalid city";
        header("location: ../../host/create.php");
        return;
    }
    //////
    /// SECTION ENDS HERE
    //////

    
}