<?php
session_start();
error_reporting(0);
include('includes/dbconnection.php');

if (isset($_POST['submit'])) {
    $fname = trim($_POST['fname'] ?? '');
    $lname = trim($_POST['lname'] ?? '');
    $email = trim($_POST['email'] ?? '');
    $mobno = trim($_POST['mobilenumber'] ?? '');
    $address = trim($_POST['address'] ?? '');
    $rawPassword = $_POST['password'] ?? '';

    // Basic sanitization
    $fname = htmlspecialchars($fname, ENT_QUOTES, 'UTF-8');
    $lname = htmlspecialchars($lname, ENT_QUOTES, 'UTF-8');
    $address = htmlspecialchars($address, ENT_QUOTES, 'UTF-8');

    if ($fname === '' || $lname === '' || $email === '' || $mobno === '' || $address === '' || $rawPassword === '') {
        echo '<script>alert("All fields are required.")</script>';
    } else {
        // Password validation pattern: minimum 8 chars, 1 uppercase, 1 lowercase, 1 special char
        $pattern = "/^(?=.*[a-z])(?=.*[A-Z])(?=.*\W).{8,}$/";

        if (!preg_match($pattern, $rawPassword)) {
            echo '<script>alert("Password must be at least 8 characters long and include at least one uppercase letter, one lowercase letter, and one special character.")</script>';
        } else {
            // Use MD5 to match current login check
            $password = md5($rawPassword);

            // Check duplicate Email or Mobile (Address can be same)
            $sqlCheck = "SELECT 1 FROM tbluser WHERE Email = ? OR MobileNumber = ? LIMIT 1";
            if ($stmt = mysqli_prepare($con, $sqlCheck)) {
                mysqli_stmt_bind_param($stmt, "ss", $email, $mobno);
                mysqli_stmt_execute($stmt);
                mysqli_stmt_store_result($stmt);

                if (mysqli_stmt_num_rows($stmt) > 0) {
                    echo '<script>alert("This email or contact number is already registered.")</script>';
                } else {
                    $sqlInsert = "INSERT INTO tbluser (FirstName, LastName, Email, MobileNumber, Password, Address) VALUES (?, ?, ?, ?, ?, ?)";
                    if ($stmtIns = mysqli_prepare($con, $sqlInsert)) {
                        mysqli_stmt_bind_param($stmtIns, "ssssss", $fname, $lname, $email, $mobno, $password, $address);
                        if (mysqli_stmt_execute($stmtIns)) {
                            echo '<script>alert("You have successfully registered")</script>';
                            echo "<script>window.location.href ='login.php'</script>";
                        } else {
                            echo '<script>alert("Something Went Wrong. Please try again")</script>';
                        }
                        mysqli_stmt_close($stmtIns);
                    }
                }
                mysqli_stmt_close($stmt);
            }
        }
    }
}
?>
<!DOCTYPE html>
<html lang="en">
<head>
    <title>AgriRentals Hub</title>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1, shrink-to-fit=no">
    <link rel="icon" href="images/logo.png" type="image/x-icon" sizes="32x32">
    <link rel="stylesheet" href="css/open-iconic-bootstrap.min.css">
    <link rel="stylesheet" href="css/animate.css">
    <link rel="stylesheet" href="css/owl.carousel.min.css">
    <link rel="stylesheet" href="css/owl.theme.default.min.css">
    <link rel="stylesheet" href="css/magnific-popup.css">
    <link rel="stylesheet" href="css/aos.css">
    <link rel="stylesheet" href="css/ionicons.min.css">
    <link rel="stylesheet" href="css/bootstrap-datepicker.css">
    <link rel="stylesheet" href="css/jquery.timepicker.css">
    <link rel="stylesheet" href="css/flaticon.css">
    <link rel="stylesheet" href="css/icomoon.css">
    <link rel="stylesheet" href="css/style.css">
</head>
<body class="goto-here">

<?php include_once('includes/header.php');?>

<div class="hero-wrap hero-bread" style="background-image: url('images/bg_1.jpg');">
    <div class="container">
        <div class="row no-gutters slider-text align-items-center justify-content-center">
            <div class="col-md-9 ftco-animate text-center">
                <p class="breadcrumbs"><span class="mr-2"><a href="index.php">Home</a></span> <span>Signup</span></p>
                <h1 class="mb-0 bread">Signup</h1>
            </div>
        </div>
    </div>
</div>

<section class="ftco-section contact-section bg-light">
    <div class="container">
        <div class="row block-9">
            <div class="col-md-12 order-md-last d-flex">
                <form class="bg-white p-5 contact-form" method="post" onsubmit="return validatePassword();">
                    <h2 style="text-align:center;font-weight:bolder;">Register with Us</h2>

                    <div class="form-group">
                        <label>First Name <span>*</span></label>
                        <input type="text" name="fname" class="form-control" required>
                    </div>

                    <div class="form-group">
                        <label>Last Name <span>*</span></label>
                        <input type="text" name="lname" class="form-control" required>
                    </div>

                    <div class="form-group">
                        <label>Email <span>*</span></label>
                        <input type="email" name="email" class="form-control" required>
                    </div>

                    <div class="form-group">
                        <label>Mobile Number <span>*</span></label>
                        <input type="text" name="mobilenumber" maxlength="10" pattern="[0-9]+" class="form-control" required>
                    </div>

                    <div class="form-group">
                        <label>Address <span>*</span></label>
                        <textarea name="address" class="form-control" rows="3" required></textarea>
                    </div>

                    <div class="form-group">
                        <label>Password <span>*</span></label>
                        <input type="password" name="password" id="password" class="form-control" 
                               required 
                               pattern="^(?=.*[a-z])(?=.*[A-Z])(?=.*\W).{8,}$" 
                               title="Must be at least 8 characters, include at least one uppercase, one lowercase and one special character">
                    </div>

                    <div class="form-group">
                        <input type="submit" name="submit" value="Sign Up" class="btn btn-primary py-3 px-5">
                    </div>
                </form>
            </div>
        </div>
    </div>
</section>

<?php include_once('includes/footer.php');?>

<script src="js/jquery.min.js"></script>
<script src="js/bootstrap.min.js"></script>
<script src="js/main.js"></script>

<script>
    // Optional extra client-side validation with JS alert for clarity
    function validatePassword() {
        const pw = document.getElementById('password').value;
        const pattern = /^(?=.*[a-z])(?=.*[A-Z])(?=.*\W).{8,}$/;
        if (!pattern.test(pw)) {
            alert("Password must be at least 8 characters long and include at least one uppercase letter, one lowercase letter, and one special character.");
            return false;
        }
        return true;
    }
</script>

</body>
</html>
