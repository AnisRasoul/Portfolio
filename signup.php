if (empty($_POST["First Name"])) {
    die("First Name is required");
}

if (!filter_var($_POST["Email"], FILTER_VALIDATE_EMAIL)) {
    die("Valid email is required");
}

if (strlen($_POST["Password"]) < 8) {
    die("Password must be at least 8 characters");
}

if (!preg_match("/[a-z]/i", $_POST["Password"])) {
    die("Password must contain at least one letter");
}

if (!preg_match("/[0-9]/", $_POST["Password"])) {
    die("Password must contain at least one number");
}

if ($_POST["Password"] !== $_POST["Confirm Password"]) {
    die("Passwords must match");
}

$password_hash = password_hash($_POST["Password"], PASSWORD_DEFAULT);

$mysqli = require __DIR__ . "/database.php";

$sql = "INSERT INTO user (First_Name, Last_Name, Birthdate, Phone_Number, Email, Password, Comment)
        VALUES (?, ?, ?, ?, ?, ?, ?)";
        
$stmt = $mysqli->stmt_init();

if (!$stmt->prepare($sql)) {
    die("SQL error: " . $mysqli->error);
}

$stmt->bind_param("sssssss",
                  $_POST["First Name"],
                  $_POST["Last Name"],
                  $_POST["Birthdate"],
                  $_POST["Phone Number"],
                  $_POST["Email"],
                  $password_hash,
                  $_POST["Comment"]);
                  
if ($stmt->execute()) {
    header("Location: signup-success.html");
    exit;
}
